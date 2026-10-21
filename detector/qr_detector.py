
#  qr_detector.py  --  QR code reader for quishing detection
#  FC382 Defense Mechanisms -- Spring 2026

#    is_supported_image(filename)   -> bool   Is the attachment a readable image?
#    decode_qr_from_file(path)      -> dict   Open the image and read its QR  [CORE]

import os
import cv2  # OpenCV: provides the QR code reader used below


class QRDetector:
    """Reads QR codes out of image attachments so their hidden text can be scanned."""

    # Image formats the bot is allowed to open. Anything else is ignored.
    SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}

    def is_supported_image(self, filename: str) -> bool:
        """
        Quick filter: return True only if the file looks like an image we
        can actually read (based on its extension). This avoids wasting time
        trying to open documents, audio, etc.
        """
        if not filename or "." not in filename:
            return False
        _, ext = os.path.splitext(filename.lower())
        return ext in self.SUPPORTED_EXTENSIONS

    def decode_qr_from_file(self, file_path: str) -> dict:
        """
        Open an image file and try to read a QR code from it.

        The return value always has the same shape so the caller can rely on it:
            success -> True if the file existed and could be opened as an image
            has_qr  -> True if a QR code was actually found and decoded
            data    -> the text/URL stored in the QR code, or None
            error   -> a short error message, or None if nothing went wrong
        """
        # Step 1: make sure the file is actually there.
        if not file_path or not os.path.exists(file_path):
            return {
                "success": False,
                "has_qr": False,
                "data": None,
                "error": "File does not exist",
            }

        # Step 2: load the image into memory. imread returns None if the file
        # is corrupt or not a real image, so we check for that.
        image = cv2.imread(file_path)
        if image is None:
            return {
                "success": False,
                "has_qr": False,
                "data": None,
                "error": "Could not read image file",
            }

        # Step 3: run OpenCV's QR detector. It returns the decoded text plus
        # the corner points of the code (points is None when no QR is found).
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(image)

        # A QR code is only "found" when we got both corner points AND text.
        if points is not None and data:
            return {
                "success": True,
                "has_qr": True,
                "data": data.strip(),
                "error": None,
            }

        # The image opened fine but contained no readable QR code.
        return {
            "success": True,
            "has_qr": False,
            "data": None,
            "error": None,
        }
