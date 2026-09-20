import qrcode from "./vendor/qrcode-generator.js";
import QrScanner from "./vendor/qr-scanner.min.js";

globalThis.HAChatQR = Object.freeze({
  encode(identity) {
    const code = qrcode(0, "M");
    code.addData(`ha-chat:${String(identity)}`, "Byte");
    code.make();
    return code.createSvgTag({cellSize: 6, margin: 4, scalable: true});
  },
  async decode(imageData) {
    try {
      const result = await QrScanner.scanImage(imageData, {returnDetailedScanResult: true});
      return result?.data || null;
    } catch {
      return null;
    }
  },
});
