import {
  pipelineServices,
  streamMetrics,
  uploadHistory,
} from "../data/ingestionMock";
import axios from "axios";

export type UploadResponse = {
  success: boolean;
  message: string;
  dataset_type?: string;
  rows_processed?: number;
  filename?: string;
};

const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

const ingestionService = {
  async getUploads() {
    await delay(400);
    return uploadHistory;
  },

  async getPipelineStatus() {
    await delay(400);
    return pipelineServices;
  },

  async getStreamMetrics() {
    await delay(400);
    return streamMetrics;
  },

  async upload(
    file: File,
    onProgress?: (percent: number) => void,
  ): Promise<UploadResponse> {
    const apiBase = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(
      /\/$/,
      "",
    );
    const formData = new FormData();
    formData.append("file", file, file.name);

    console.log("Calling backend...");

    try {
      const response = await axios.post<UploadResponse>(
        `${apiBase}/api/upload`,
        formData,
        {
          onUploadProgress: (event) => {
            if (event.total && onProgress) {
              onProgress(Math.round((event.loaded / event.total) * 100));
            }
          },
        },
      );

      console.log(response);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = error.response?.data?.detail;
        const message =
          typeof detail === "string"
            ? detail
            : detail?.message || error.message;
        throw new Error(message);
      }

      throw error;
    }
  },
};

export default ingestionService;
