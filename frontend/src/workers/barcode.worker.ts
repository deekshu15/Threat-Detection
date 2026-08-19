import { MultiFormatReader, RGBLuminanceSource, HybridBinarizer, BinaryBitmap } from '@zxing/library';

const reader = new MultiFormatReader();

self.onmessage = (event: MessageEvent) => {
  const { buffer, width, height, id } = event.data;
  const rgba = new Uint8ClampedArray(buffer);

  const grayscale = new Uint8ClampedArray(width * height);
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
    const luminanceSource = new RGBLuminanceSource(grayscale, width, height);
    const binaryBitmap = new BinaryBitmap(new HybridBinarizer(luminanceSource));
    const result = reader.decodeWithState(binaryBitmap);

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
