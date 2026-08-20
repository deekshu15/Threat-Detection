import { MultiFormatReader, RGBLuminanceSource, HybridBinarizer, BinaryBitmap, DecodeHintType, BarcodeFormat } from '@zxing/library';

const reader = new MultiFormatReader();

function buildHints() {
  const hints = new Map();
  hints.set(DecodeHintType.TRY_HARDER, true);
  hints.set(DecodeHintType.POSSIBLE_FORMATS, [
    BarcodeFormat.QR_CODE,
    BarcodeFormat.DATA_MATRIX,
    BarcodeFormat.AZTEC,
    BarcodeFormat.PDF_417,
    BarcodeFormat.CODE_128,
    BarcodeFormat.CODE_39,
    BarcodeFormat.CODE_93,
    BarcodeFormat.CODABAR,
    BarcodeFormat.EAN_13,
    BarcodeFormat.EAN_8,
    BarcodeFormat.UPC_A,
    BarcodeFormat.UPC_E,
    BarcodeFormat.ITF,
    BarcodeFormat.RSS_14,
    BarcodeFormat.RSS_EXPANDED,
  ]);
  return hints;
}

function downscaleImageData(imageData: ImageData, maxDim = 1024): ImageData {
  const { width, height } = imageData;
  const longest = Math.max(width, height);

  if (longest <= maxDim) {
    return imageData;
  }

  const scale = maxDim / longest;
  const newWidth = Math.round(width * scale);
  const newHeight = Math.round(height * scale);

  const canvas = new OffscreenCanvas(newWidth, newHeight);
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return imageData;
  }

  const srcCanvas = new OffscreenCanvas(width, height);
  const srcCtx = srcCanvas.getContext('2d');
  if (!srcCtx) {
    return imageData;
  }
  srcCtx.putImageData(imageData, 0, 0);

  ctx.drawImage(srcCanvas, 0, 0, width, height, 0, 0, newWidth, newHeight);

  return ctx.getImageData(0, 0, newWidth, newHeight);
}

self.onmessage = (event: MessageEvent) => {
  const { buffer, width, height, id } = event.data;
  let imageData = new ImageData(new Uint8ClampedArray(buffer), width, height);

  try {
    imageData = downscaleImageData(imageData, 1024);
  } catch {
    // proceed with original image if downscale fails
  }

  const rgba = imageData.data;
  const w = imageData.width;
  const h = imageData.height;

  const grayscale = new Uint8ClampedArray(w * h);
  for (let i = 0, j = 0; i < rgba.length; i += 4, j++) {
    const alpha = rgba[i + 3];
    if (alpha === 0) {
      grayscale[j] = 0xff;
    } else {
      const pixelR = rgba[i];
      const pixelG = rgba[i + 1];
      const pixelB = rgba[i + 2];
      grayscale[j] = (306 * pixelR + 601 * pixelG + 117 * pixelB + 0x200) >> 10;
    }
  }

  try {
    const luminanceSource = new RGBLuminanceSource(grayscale, w, h);
    const binaryBitmap = new BinaryBitmap(new HybridBinarizer(luminanceSource));
    const hints = buildHints();
    const result = reader.decode(binaryBitmap, hints);

    self.postMessage({
      id,
      success: true,
      text: result.getText(),
      format: result.getBarcodeFormat(),
    });
  } catch (error) {
    self.postMessage({
      id,
      success: false,
      error: error instanceof Error ? error.message : 'Unknown decoding error',
    });
  }
};
