#  bot.py  --  Main Discord bot (events, scanning workflow, commands)
#  FC382 Defense Mechanisms -- Spring 2026

#    -- helpers --
#    has_trusted_role(member)     -> bool   May this member skip scanning?
#    has_admin_role(member)       -> bool   May this member restore a message?
#    format_incident_data(...)    -> dict   Build the record written to the log
#    log_incident(incident)               Write one incident line to the log
#    log_restore_action(...)              Record that an admin restored a msg
#
#    -- Discord UI / notifications --
#    class RestoreView                    The "Restore as Exception" button
#    send_warning_embed(...)              Public warning in the channel
#    send_security_log(...)               Forward the incident to #security-logs
#
#    -- scanning workflow (the core) --
#    scan_text_message(message)   -> bool   Scan the text of a message   [CORE]
#    scan_attachments(message)    -> bool   Scan image/QR attachments    [CORE]
#
#    -- events & commands --
#    on_ready()                           Runs once when the bot connects
#    on_message(message)                  Entry point for every message [CORE]
#    ping_command / manual_scan / helpme_command   The !commands

import os
import json
import logging
from datetime import datetime

import discord
from discord.ext import commands
from dotenv import load_dotenv

from detector.phishing_detector import PhishingDetector
from detector.qr_detector import QRDetector


# CONFIGURATION  --  read settings from the .env file
# Keeping secrets (the token) out of the code is a basic security practice.

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
BOT_PREFIX = os.getenv("BOT_PREFIX", "!")
# Toggle so we can demo "detect only" vs "detect and delete" without code edits.
DELETE_SUSPICIOUS_MESSAGES = os.getenv("DELETE_SUSPICIOUS_MESSAGES", "true").lower() == "true"
LOG_CHANNEL_ID = os.getenv("LOG_CHANNEL_ID", "").strip()

# Fail fast with a clear message if the bot token was never set.
if not TOKEN:
    raise ValueError("DISCORD_TOKEN is missing in the .env file.")



# ROLES  --  who is exempt, and who can override the bot
# NOTE: role names are stored in lowercase here and compared case-insensitively,
# so "Admin", "admin", or " ADMIN " all match correctly regardless of how the
# role is spelled in the Discord server.


# Members with one of these roles are never scanned. This stops the bot from
# flagging legitimate posts such as official announcements by staff.
TRUSTED_ROLES = {"admin", "moderator", "announcer"}

# Only these roles are allowed to press "Restore" and bring back a deleted msg.
ADMIN_ROLES = {"admin", "moderator"}



# LOGGING  --  send every incident to a file AND to the console


os.makedirs("logs", exist_ok=True)   # folder for the persistent attack log
os.makedirs("temp", exist_ok=True)   # folder for temporarily saved QR images

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("logs/attacks.log", encoding="utf-8"),  # file copy
        logging.StreamHandler(),                                    # live console
    ],
)

logger = logging.getLogger("phishing_bot")



# DISCORD CLIENT  --  set up the bot and its permissions (intents)
# NOTE: "message_content" must also be enabled in the Discord Developer Portal,
# otherwise the bot receives empty messages and cannot scan anything.


intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.messages = True
intents.members = True

bot = commands.Bot(command_prefix=BOT_PREFIX, intents=intents)

# Create one shared instance of each detector for the whole bot to reuse.
phishing_detector = PhishingDetector()
qr_detector = QRDetector()



# HELPER FUNCTIONS


def has_trusted_role(member: discord.Member) -> bool:
    """Return True if the member is exempt from scanning."""
    if not isinstance(member, discord.Member):
        return False
    # Primary check: anyone with the Administrator or Manage Messages
    # permission is treated as staff and exempted, NO MATTER what their role
    # is named. This is the reliable check because it does not depend on the
    # exact spelling of the role name in the server.
    perms = member.guild_permissions
    if perms.administrator or perms.manage_messages:
        return True
    # Fallback: also exempt by role name (case-insensitive), in case a staff
    # role exists without those permissions.
    return any(role.name.strip().lower() in TRUSTED_ROLES for role in member.roles)


def has_admin_role(member: discord.Member) -> bool:
    """Return True if the member is allowed to restore deleted messages."""
    if not isinstance(member, discord.Member):
        return False
    # Same logic: Administrator / Manage Messages permission, or a named role.
    perms = member.guild_permissions
    if perms.administrator or perms.manage_messages:
        return True
    return any(role.name.strip().lower() in ADMIN_ROLES for role in member.roles)


def format_incident_data(message: discord.Message, detection_result: dict, source: str) -> dict:
    """
    Package everything we know about a flagged message into one tidy record.
    This single dict is what gets logged and what feeds the security embed.
    'source' says where the detection came from: "text_message" or "qr_attachment".
    """
    return {
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "guild": message.guild.name if message.guild else "DM",
        "channel": message.channel.name if hasattr(message.channel, "name") else "Unknown",
        "author": str(message.author),
        "author_id": message.author.id,
        "message_content": message.content,
        # For QR attachments the dangerous link lives inside the image, not in
        # message_content. scan_attachments() fills this in so the restore step
        # can still show what the QR contained.
        "qr_content": None,
        "risk_score": detection_result.get("risk_score", 0),
        "is_phishing": detection_result.get("is_phishing", False),
        "reasons": detection_result.get("reasons", []),
        "urls_found": detection_result.get("urls_found", []),
    }


def log_incident(incident: dict) -> None:
    """Write one incident to the log as a single JSON line (easy to parse later)."""
    logger.warning(json.dumps(incident, ensure_ascii=False))


def log_restore_action(original_incident: dict, admin: discord.Member) -> None:
    """
    Record that an admin overrode the bot and restored a deleted message.
    Keeping this audit trail shows who approved each exception and why.
    """
    restore_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": "restored_as_exception",
        "restored_by": str(admin),
        "restored_by_id": admin.id,
        "original_author": original_incident.get("author"),
        "original_author_id": original_incident.get("author_id"),
        "original_channel": original_incident.get("channel"),
        "original_risk_score": original_incident.get("risk_score"),
        "original_content": original_incident.get("message_content"),
        # Keep the QR payload in the audit trail too, when present.
        "original_qr_content": original_incident.get("qr_content"),
    }
    logger.warning(json.dumps(restore_record, ensure_ascii=False))



# RESTORE BUTTON  --  the interactive control attached to each log entry


class RestoreView(discord.ui.View):
    """
    The button shown under every incident in the log channel.
    If the bot makes a mistake (false positive), an admin can press this to
    repost the original message and have the override recorded in the log.
    """

    def __init__(self, original_channel: discord.TextChannel, incident: dict):
        # timeout=None keeps the button working forever, even after a restart.
        super().__init__(timeout=None)
        self.original_channel = original_channel
        self.incident = incident

    @discord.ui.button(label="Restore as Exception", style=discord.ButtonStyle.success)
    async def restore_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Permission check: ignore the click unless the user is an admin/mod.
        if not has_admin_role(interaction.user):
            await interaction.response.send_message(
                "You do not have permission to restore messages.",
                ephemeral=True,   # only the clicker sees this reply
            )
            return

        try:
            original_author = self.incident.get("author", "Unknown")
            original_author_id = self.incident.get("author_id", "Unknown")
            original_content = self.incident.get("message_content", "") or ""
            qr_content = self.incident.get("qr_content")

            # Build the content section. For a QR-based incident the text is in
            # the image, so we show the decoded QR content instead of (or in
            # addition to) any plain message text.
            if qr_content:
                if original_content.strip():
                    content_section = f"{original_content}\nQR code content: {qr_content}"
                else:
                    content_section = f"QR code content: {qr_content}"
            else:
                content_section = original_content if original_content.strip() else "(no content)"

            # Repost the original content with a note explaining the override.
            restored_text = (
                f"Message restored by administrator {interaction.user.mention} "
                f"as an exception.\n"
                f"Original author: {original_author} (ID: {original_author_id})\n"
                f"Original content:\n{content_section}"
            )

            await self.original_channel.send(restored_text)
            log_restore_action(self.incident, interaction.user)

            # Grey out the button so the same incident cannot be restored twice.
            button.disabled = True
            button.label = f"Restored by {interaction.user.name}"
            await interaction.response.edit_message(view=self)

        except discord.Forbidden:
            # The bot lacks permission to post in the original channel.
            await interaction.response.send_message(
                "Bot does not have permission to post in the original channel.",
                ephemeral=True,
            )
        except Exception as error:
            logger.error(f"Failed to restore message: {error}")
            await interaction.response.send_message(
                "An error occurred while restoring the message.",
                ephemeral=True,
            )



# NOTIFICATIONS  --  the messages the bot posts when it acts


async def send_warning_embed(channel: discord.TextChannel, user: discord.User, reasons: list[str]) -> None:
    """
    Post a short, public warning in the channel where the threat appeared,
    so other members can see the message was removed and why. It self-deletes
    after 15 seconds to avoid cluttering the channel.
    """
    embed = discord.Embed(
        title="Suspicious Message Detected",
        description=(
            f"A potentially malicious message from {user.mention} "
            f"(ID: {user.id}) was detected and removed."
        ),
        color=discord.Color.red(),
    )

    # Show up to 5 reasons so the warning stays readable.
    if reasons:
        embed.add_field(
            name="Detection Reasons",
            value="\n".join(f"- {reason}" for reason in reasons[:5]),
            inline=False,
        )

    embed.set_footer(text="Discord Phishing and Quishing Detector")
    await channel.send(embed=embed, delete_after=15)


async def send_security_log(
    guild: discord.Guild,
    incident: dict,
    original_channel: discord.TextChannel,
) -> None:
    """
    Send a detailed record of the incident to the dedicated #security-logs
    channel for the moderators. It includes the Restore button so a false
    positive can be reversed. Does nothing if no log channel is configured.
    """
    if not LOG_CHANNEL_ID:
        return

    try:
        log_channel = guild.get_channel(int(LOG_CHANNEL_ID))
        if log_channel is None:
            return

        embed = discord.Embed(
            title="Security Incident Logged",
            color=discord.Color.orange(),
            timestamp=datetime.now(),
        )

        # Key facts, shown side by side for a quick read.
        embed.add_field(name="User", value=incident["author"], inline=True)
        embed.add_field(name="User ID", value=str(incident["author_id"]), inline=True)
        embed.add_field(name="Channel", value=incident["channel"], inline=True)
        embed.add_field(name="Risk Score", value=str(incident["risk_score"]), inline=True)
        embed.add_field(name="Source", value=incident["source"], inline=True)

        reason_text = (
            "\n".join(f"- {r}" for r in incident["reasons"][:5])
            if incident["reasons"]
            else "No reasons captured"
        )
        embed.add_field(name="Reasons", value=reason_text, inline=False)

        # For QR incidents the message text is empty, so prefer the decoded QR
        # content for the preview when it exists.
        preview_source = incident["message_content"] or incident.get("qr_content") or ""
        msg_preview = preview_source[:300] if preview_source else "(No text content)"
        embed.add_field(name="Message Preview", value=msg_preview, inline=False)

        view = RestoreView(original_channel=original_channel, incident=incident)
        await log_channel.send(embed=embed, view=view)

    except Exception as error:
        logger.error(f"Failed to send security log: {error}")



# SCANNING WORKFLOW  --  the steps taken once a threat is confirmed
# Both scanners follow the same pattern: log -> (optionally) delete ->
# warn the channel -> send the detailed security log.


async def scan_text_message(message: discord.Message) -> bool:
    """
    Scan the plain text of a message for phishing (links + wording).
    Returns True if the message was flagged and the bot acted on it.
    """
    detection_result = phishing_detector.analyze_text(message.content)

    # Nothing suspicious -> let the message through.
    if not detection_result["is_phishing"]:
        return False

    # 1) Record the incident.
    incident = format_incident_data(message, detection_result, source="text_message")
    log_incident(incident)

    # 2) Remove the message (only if deletion is enabled in the config).
    if DELETE_SUSPICIOUS_MESSAGES:
        try:
            await message.delete()
        except discord.Forbidden:
            logger.error("Missing permission to delete messages.")
        except discord.NotFound:
            logger.warning("Message was already deleted before the bot could act.")
        except Exception as error:
            logger.error(f"Unexpected error while deleting message: {error}")

    # 3) Warn the channel, and 4) send the detailed log to the mods.
    await send_warning_embed(message.channel, message.author, detection_result["reasons"])

    if message.guild:
        await send_security_log(message.guild, incident, message.channel)

    return True


async def scan_attachments(message: discord.Message) -> bool:
    """
    Scan image attachments for QR-code phishing ("quishing").
    For each supported image: save it, read the QR, then run the QR's hidden
    text through the same phishing detector used for normal messages.
    Returns True if a malicious QR code was found and acted on.
    """
    if not message.attachments:
        return False

    for attachment in message.attachments:
        # Skip anything that is not an image we can open.
        if not qr_detector.is_supported_image(attachment.filename):
            continue

        temp_path = os.path.join("temp", attachment.filename)

        try:
            # Download the image, then try to read a QR code out of it.
            await attachment.save(temp_path)
            qr_result = qr_detector.decode_qr_from_file(temp_path)

            # No readable QR in this image -> move on to the next attachment.
            if not qr_result["success"] or not qr_result["has_qr"]:
                continue

            # Score the hidden text exactly like a normal message.
            qr_text = qr_result["data"]
            detection_result = phishing_detector.analyze_text(qr_text)

            # Add a reason line that shows the demo what was hidden in the QR.
            detection_result["reasons"].insert(
                0, f"QR code detected with embedded content: {qr_text[:100]}"
            )

            # +1 extra point: hiding a link inside a QR is itself a risk because
            # the user cannot see the destination. Source: Barracuda QR report 2024.
            detection_result["risk_score"] += 1

            # Re-check the verdict after adding the QR bonus point.
            if detection_result["risk_score"] >= 3:
                detection_result["is_phishing"] = True

            # Still below the threshold -> not malicious, keep going.
            if not detection_result["is_phishing"]:
                continue

            # Same response steps as the text scanner: log -> delete -> warn -> report.
            incident = format_incident_data(message, detection_result, source="qr_attachment")
            # Store the decoded QR text so the Restore button can display the
            # hidden link (message.content is empty for image-only messages).
            incident["qr_content"] = qr_text
            log_incident(incident)

            if DELETE_SUSPICIOUS_MESSAGES:
                try:
                    await message.delete()
                except discord.Forbidden:
                    logger.error("Missing permission to delete QR-based phishing message.")
                except discord.NotFound:
                    logger.warning("QR message was already deleted.")
                except Exception as error:
                    logger.error(f"Unexpected error deleting QR message: {error}")

            await send_warning_embed(message.channel, message.author, detection_result["reasons"])

            if message.guild:
                await send_security_log(message.guild, incident, message.channel)

            return True

        except Exception as error:
            logger.error(f"Attachment scanning failed for '{attachment.filename}': {error}")

        finally:
            # Always clean up the temporary image, success or failure.
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    logger.warning(f"Could not remove temp file: {temp_path}")

    return False



# EVENTS  --  code that Discord calls automatically


@bot.event
async def on_ready():
    """Runs once after the bot logs in. Prints the active settings for the demo."""
    logger.info(f"Bot online. Logged in as {bot.user} (ID: {bot.user.id})")
    logger.info(f"Delete suspicious messages: {DELETE_SUSPICIOUS_MESSAGES}")
    logger.info(f"Trusted roles: {', '.join(TRUSTED_ROLES)}")
    logger.info(f"Log channel ID: {LOG_CHANNEL_ID or 'Not configured'}")


@bot.event
async def on_message(message: discord.Message):
    """
    The main entry point: Discord calls this for EVERY message.
    The message is filtered and then scanned in this order:
        1. ignore the bot's own messages
        2. let bot commands (e.g. !scan) pass through to the command handler
        3. skip members who have a trusted role
        4. scan the text   -> stop if flagged
        5. scan attachments -> stop if flagged
    """
    # 1) Never scan the bot's own messages (avoids an infinite loop).
    if message.author.bot:
        return

    # 2) Commands start with the prefix; hand them to the command handler.
    #    This also lets users freely test the detector with !scan.
    if message.content.startswith(BOT_PREFIX):
        await bot.process_commands(message)
        return

    # 3) Trusted members (admins, mods, announcers) are exempt from scanning.
    #    DEBUG: print exactly which roles the bot sees for this author and the
    #    exemption decision. Watch this line in the terminal to confirm your
    #    role is being recognised. Remove it once everything works.
    if isinstance(message.author, discord.Member):
        role_names = [r.name for r in message.author.roles]
        logger.info(
            f"[DEBUG] author={message.author} roles={role_names} "
            f"trusted={has_trusted_role(message.author)}"
        )

    if isinstance(message.author, discord.Member) and has_trusted_role(message.author):
        await bot.process_commands(message)
        return

    # 4) Scan the message text. If it was flagged, we are done.
    text_detected = await scan_text_message(message)
    if text_detected:
        return

    # 5) Otherwise scan any image attachments for QR phishing.
    qr_detected = await scan_attachments(message)
    if qr_detected:
        return

    # Nothing flagged: still allow normal commands to run.
    await bot.process_commands(message)



# COMMANDS  --  the manual !commands used in the demo


@bot.command(name="ping")
async def ping_command(ctx: commands.Context):
    """Simple health check: replies with the bot's current latency."""
    await ctx.send(f"Pong. Latency: {round(bot.latency * 1000)} ms")


@bot.command(name="scan")
async def manual_scan(ctx: commands.Context, *, text: str):
    """
    Manually run the detector on any text (great for a live demo).
    Example:
        !scan free nitro click here http://bit.ly/abc
    """
    result = phishing_detector.analyze_text(text)

    # Red embed if flagged, green if it looks clean.
    embed = discord.Embed(
        title="Manual Scan Result",
        color=discord.Color.red() if result["is_phishing"] else discord.Color.green(),
    )
    embed.add_field(name="Is Suspicious", value="Yes" if result["is_phishing"] else "No", inline=True)
    embed.add_field(name="Risk Score", value=str(result["risk_score"]), inline=True)
    embed.add_field(name="URLs Found", value=str(len(result["urls_found"])), inline=True)

    reason_text = (
        "\n".join(f"- {r}" for r in result["reasons"])
        if result["reasons"]
        else "No suspicious indicators found."
    )
    embed.add_field(name="Reasons", value=reason_text[:1024], inline=False)

    await ctx.send(embed=embed)


@bot.command(name="helpme")
async def helpme_command(ctx: commands.Context):
    """List every command the bot supports."""
    embed = discord.Embed(
        title="Discord Phishing Detector Bot",
        description="Available commands:",
        color=discord.Color.blue(),
    )
    embed.add_field(name="!ping", value="Check bot latency.", inline=False)
    embed.add_field(name="!scan <text>", value="Manually test a message against the detector.", inline=False)
    embed.add_field(name="!helpme", value="Show this help message.", inline=False)
    embed.set_footer(text="FC382 Defense Mechanisms - Spring 2026")
    await ctx.send(embed=embed)



# START THE BOT  --  this line connects to Discord and runs forever


bot.run(TOKEN)
