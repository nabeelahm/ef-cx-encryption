package com.ef.encryption.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Utility class for compressing and decompressing byte arrays using GZIP.
 */
public class CompressionUtil {

    private CompressionUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * Compresses the given byte array using GZIP.
     *
     * @param data the byte array to compress
     * @return the compressed byte array
     * @throws Exception if an I/O error occurs during compression
     */
    public static byte[] compress(byte[] data) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipStream = new GZIPOutputStream(byteStream)) {
            gzipStream.write(data);
        }
        return byteStream.toByteArray();
    }

    /**
     * Decompresses the given GZIP-compressed byte array.
     *
     * @param compressedData the compressed byte array to decompress
     * @return the decompressed byte array
     * @throws Exception if an I/O error occurs during decompression
     */
    public static byte[] decompress(byte[] compressedData) throws Exception {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(compressedData);
        try (GZIPInputStream gzipStream = new GZIPInputStream(byteStream);
                ByteArrayOutputStream outStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzipStream.read(buffer)) != -1) {
                outStream.write(buffer, 0, len);
            }
            return outStream.toByteArray();
        }
    }
}
