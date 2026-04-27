package com.ding.rtc.audio;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaCrypto;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.os.Build;
import android.view.Surface;
import com.google.android.exoplayer2.source.hls.DefaultHlsExtractorFactory;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.ByteBuffer;
import org.webrtc.mozi.ContextUtils;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
public class MediaCodecAudioDecoder {
    private Context mContext;
    private long mFileLength;
    private ByteBuffer[] mInputBuffers;
    private boolean mIsMeizu;
    private boolean mIsMeizuMX4;
    private boolean mIsVivo;
    private long mNativeHandle;
    private ByteBuffer[] mOutputBuffers;
    private static String TAG = "MediaCodecAudioDecoder";
    private static int MAX_DECODER_RETRY_COUNT = 64;
    private static int HTTP_REQUEST_TIMEOUT = 6000;
    private static int DECODE_READ_BUFFER_SIZE = 98304;
    private boolean mInputStreamEnd = false;
    private boolean mOutputStreamEnd = false;
    private ByteBuffer mDecodeReadBuffer = ByteBuffer.allocateDirect(DECODE_READ_BUFFER_SIZE);
    private MediaCodec mMediaCodec = null;
    private MediaExtractor mExtractor = null;
    private MediaFormat mTrackFormat = null;
    private boolean mDecodeIsReady = false;
    private int mSampleRate = 48000;
    private int mChannels = 2;
    private int mRetryCount = 0;
    MediaCodec.BufferInfo mInfo = new MediaCodec.BufferInfo();

    private native void nativeCacheDirectBufferAddress(long nativeHandle, ByteBuffer byteBuffer);

    private native void nativeCodecInit(long nativeHandle, int sampleRate, int channels, long frameLength);

    private native void nativeDataBufferIsReady(long nativeHandle, int bytes, int sampleRate, int channels);

    public MediaCodecAudioDecoder(long nativeHandle) {
        this.mContext = null;
        boolean z = false;
        this.mNativeHandle = 0L;
        this.mIsMeizu = false;
        this.mIsVivo = false;
        this.mIsMeizuMX4 = false;
        this.mNativeHandle = nativeHandle;
        this.mContext = ContextUtils.getApplicationContext();
        this.mIsMeizu = Build.BRAND.toLowerCase().contains("meizu") || Build.MANUFACTURER.toLowerCase().contains("meizu");
        this.mIsVivo = Build.BRAND.toLowerCase().contains("vivo") || Build.MANUFACTURER.toLowerCase().contains("vivo");
        if (this.mIsMeizu && Build.MODEL.equals("MX4")) {
            z = true;
        }
        this.mIsMeizuMX4 = z;
    }

    public int initDecoder(String filename, long startPosUs) {
        try {
            this.mRetryCount = 0;
            this.mDecodeReadBuffer.clear();
            Logging.d(TAG, "open Audio File name:" + filename);
            boolean isHttpFile = filename.toLowerCase().startsWith("http");
            boolean isMP3File = filename.endsWith(DefaultHlsExtractorFactory.MP3_FILE_EXTENSION) || filename.endsWith(".MP3");
            boolean isAssetsFile = filename.startsWith("/assets/");
            boolean isAssetFile2 = filename.startsWith("file:///android_asset/");
            this.mExtractor = new MediaExtractor();
            if (this.mIsMeizuMX4 && isMP3File) {
                Logging.e(TAG, " Meizu mx4 does not support mp3 hw decoder:" + filename);
                return -8;
            }
            if (isAssetsFile) {
                if (this.mContext == null) {
                    return -1;
                }
                try {
                    AssetFileDescriptor assetfd = this.mContext.getAssets().openFd(filename.substring("/assets/".length()));
                    this.mExtractor.setDataSource(assetfd.getFileDescriptor(), assetfd.getStartOffset(), assetfd.getLength());
                    assetfd.close();
                } catch (IOException e) {
                    Logging.e(TAG, "Failed to open assert File:" + filename);
                    return -2;
                }
            } else if (isAssetFile2) {
                if (this.mContext == null) {
                    return -1;
                }
                try {
                    AssetFileDescriptor assetfd2 = this.mContext.getAssets().openFd(filename.substring("file:///android_asset/".length()));
                    this.mExtractor.setDataSource(assetfd2.getFileDescriptor(), assetfd2.getStartOffset(), assetfd2.getLength());
                } catch (IOException e2) {
                    Logging.e(TAG, "Failed to open assert2 File:" + filename);
                    return -2;
                }
            } else if (isHttpFile) {
                try {
                    HttpURLConnection.setFollowRedirects(true);
                    HttpURLConnection con = (HttpURLConnection) new URL(filename).openConnection();
                    con.setConnectTimeout(HTTP_REQUEST_TIMEOUT);
                    con.setReadTimeout(HTTP_REQUEST_TIMEOUT);
                    con.connect();
                    int responseCode = con.getResponseCode();
                    if (responseCode != 200 && responseCode != 301 && responseCode != 302) {
                        Logging.e(TAG, "Failed to Connect URL: " + filename + ", responseCode: " + responseCode);
                        return -3;
                    }
                    this.mExtractor.setDataSource(filename);
                } catch (SocketTimeoutException e3) {
                    Logging.e(TAG, "Failed to Connect URL:" + filename + " timeout!");
                    return -4;
                } catch (IOException ex) {
                    Logging.e(TAG, "Failed to Connect URL:" + filename + " exception!");
                    ex.printStackTrace();
                    return -5;
                }
            } else {
                this.mExtractor.setDataSource(filename);
            }
            int nTrackCount = this.mExtractor.getTrackCount();
            for (int i = 0; i < nTrackCount; i++) {
                this.mExtractor.unselectTrack(i);
            }
            int i2 = 0;
            while (true) {
                if (i2 >= nTrackCount) {
                    break;
                }
                MediaFormat trackFormat = this.mExtractor.getTrackFormat(i2);
                this.mTrackFormat = trackFormat;
                String mimeType = trackFormat.getString("mime");
                if (!mimeType.contains("audio/")) {
                    i2++;
                } else {
                    this.mExtractor.selectTrack(i2);
                    MediaCodec mediaCodecCreateDecoderByType = MediaCodec.createDecoderByType(mimeType);
                    this.mMediaCodec = mediaCodecCreateDecoderByType;
                    mediaCodecCreateDecoderByType.configure(this.mTrackFormat, (Surface) null, (MediaCrypto) null, 0);
                    break;
                }
            }
            if (this.mMediaCodec == null) {
                return -6;
            }
            if (startPosUs > 0) {
                this.mExtractor.seekTo(startPosUs, 2);
            }
            this.mMediaCodec.start();
            this.mSampleRate = this.mTrackFormat.getInteger("sample-rate");
            this.mChannels = this.mTrackFormat.getInteger("channel-count");
            long j = this.mTrackFormat.getLong("durationUs");
            this.mFileLength = j;
            nativeCodecInit(this.mNativeHandle, this.mSampleRate, this.mChannels, j);
            nativeCacheDirectBufferAddress(this.mNativeHandle, this.mDecodeReadBuffer);
            Logging.d(TAG, "open Audio File name:" + filename + " succ!");
            return 0;
        } catch (Exception ex2) {
            Logging.e(TAG, "Failed to open file:" + filename);
            ex2.printStackTrace();
            return -7;
        }
    }

    public int getAudioChannels() {
        return this.mChannels;
    }

    public int getAudioSampleRate() {
        return this.mSampleRate;
    }

    public long getFileLength() {
        return this.mFileLength;
    }

    public void rewindDecoder() {
        try {
            this.mExtractor.seekTo(0L, 1);
            this.mMediaCodec.flush();
        } catch (Exception e) {
            Logging.e(TAG, "Failed to rewind file!");
        }
        this.mInputStreamEnd = false;
        this.mOutputStreamEnd = false;
        this.mDecodeIsReady = false;
    }

    public void releaseDecoder() {
        try {
            if (this.mMediaCodec != null) {
                this.mMediaCodec.stop();
                this.mMediaCodec.release();
                this.mMediaCodec = null;
            }
            if (this.mExtractor != null) {
                this.mExtractor.release();
                this.mExtractor = null;
            }
        } catch (Exception e) {
            Logging.e(TAG, "Failed to releaseDecoder file!");
            e.printStackTrace();
        }
        Logging.d(TAG, "releaseDecoder!");
        this.mOutputStreamEnd = false;
        this.mInputStreamEnd = false;
    }

    private void dequeueInputBuffer() {
        ByteBuffer inBuf;
        int sampleSize;
        int index = this.mMediaCodec.dequeueInputBuffer(0L);
        if (index >= 0) {
            if (Build.VERSION.SDK_INT >= 21) {
                inBuf = this.mMediaCodec.getInputBuffer(index);
            } else {
                ByteBuffer[] inputBuffers = this.mMediaCodec.getInputBuffers();
                this.mInputBuffers = inputBuffers;
                inBuf = inputBuffers[index];
            }
            long sampleTime = this.mExtractor.getSampleTime();
            int flags = this.mExtractor.getSampleFlags();
            int sampleSize2 = this.mExtractor.readSampleData(inBuf, 0);
            if (sampleSize2 > 0) {
                sampleSize = sampleSize2;
            } else {
                this.mInputStreamEnd = true;
                flags |= 4;
                sampleSize = 0;
            }
            this.mMediaCodec.queueInputBuffer(index, 0, sampleSize, sampleTime, flags);
            this.mExtractor.advance();
        }
    }

    private void dequeueOutputBuffer() {
        int index = this.mMediaCodec.dequeueOutputBuffer(this.mInfo, 0L);
        this.mDecodeIsReady = false;
        if (index == -3 || index == -2) {
            return;
        }
        if (index == -1) {
            int i = this.mRetryCount + 1;
            this.mRetryCount = i;
            if (i >= MAX_DECODER_RETRY_COUNT) {
                if (this.mIsMeizu || this.mIsVivo) {
                    Logging.e(TAG, "Failed to dequeueBuffer trycount=" + this.mRetryCount + " presentationTime=" + this.mInfo.presentationTimeUs + " total=" + this.mFileLength);
                    this.mRetryCount = 0;
                    this.mOutputStreamEnd = true;
                    return;
                }
                return;
            }
            return;
        }
        if (index >= 0) {
            this.mRetryCount = 0;
            if ((this.mInfo.flags & 4) != 0) {
                this.mOutputStreamEnd = true;
            }
            if (Build.VERSION.SDK_INT >= 21) {
                ByteBuffer outbuf = this.mMediaCodec.getOutputBuffer(index);
                copyToReadBuffer(outbuf, outbuf.limit());
            } else {
                ByteBuffer[] outputBuffers = this.mMediaCodec.getOutputBuffers();
                this.mOutputBuffers = outputBuffers;
                copyToReadBuffer(outputBuffers[index], this.mInfo.size);
            }
            this.mMediaCodec.releaseOutputBuffer(index, false);
            this.mDecodeIsReady = true;
        }
    }

    public boolean decodeData() {
        try {
            if (!this.mInputStreamEnd) {
                dequeueInputBuffer();
            }
            if (!this.mOutputStreamEnd) {
                dequeueOutputBuffer();
            }
            return this.mOutputStreamEnd;
        } catch (Exception ex) {
            Logging.e(TAG, "Failed to decode data!");
            ex.printStackTrace();
            return false;
        }
    }

    private boolean checkAudioFormatChange() {
        if (Build.VERSION.SDK_INT < 16) {
            return false;
        }
        boolean change = false;
        try {
            MediaFormat newformat = this.mMediaCodec.getOutputFormat();
            int new_channels = newformat.getInteger("channel-count");
            int new_rate = newformat.getInteger("sample-rate");
            if (this.mSampleRate != new_rate || this.mChannels != new_channels) {
                change = true;
            }
            this.mSampleRate = new_rate;
            this.mChannels = new_channels;
            return change;
        } catch (Exception e) {
            Logging.e(TAG, "Failed to get new audio format!");
            return false;
        }
    }

    private void copyToReadBuffer(ByteBuffer inputBuffer, int length) {
        int readBytes;
        int pos = 0;
        boolean bResetPos = false;
        try {
            checkAudioFormatChange();
            while (pos < length) {
                int readBytes2 = length - pos;
                if (readBytes2 <= DECODE_READ_BUFFER_SIZE) {
                    readBytes = readBytes2;
                } else {
                    bResetPos = true;
                    readBytes = DECODE_READ_BUFFER_SIZE;
                }
                if (bResetPos) {
                    inputBuffer.position(pos);
                    inputBuffer.limit(pos + readBytes);
                }
                this.mDecodeReadBuffer.position(0);
                this.mDecodeReadBuffer.put(inputBuffer);
                nativeDataBufferIsReady(this.mNativeHandle, readBytes, this.mSampleRate, this.mChannels);
                pos += readBytes;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static boolean isAACSupported() {
        boolean supported = true;
        try {
            if (Build.VERSION.SDK_INT >= 21) {
                MediaCodecList codecList = new MediaCodecList(1);
                MediaCodecInfo[] codecInfos = codecList.getCodecInfos();
                int length = codecInfos.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    }
                    MediaCodecInfo codecInfo = codecInfos[i];
                    if (!codecInfo.isEncoder()) {
                        String name = codecInfo.getName().toLowerCase();
                        if (name.contains("nvidia")) {
                            supported = false;
                            break;
                        }
                    }
                    i++;
                }
                return supported;
            }
            int numCodecs = MediaCodecList.getCodecCount();
            for (int i2 = 0; i2 < numCodecs; i2++) {
                MediaCodecInfo codecInfo2 = MediaCodecList.getCodecInfoAt(i2);
                if (!codecInfo2.isEncoder()) {
                    String name2 = codecInfo2.getName().toLowerCase();
                    if (name2.contains("nvidia")) {
                        return false;
                    }
                }
            }
            return true;
        } catch (Exception ex) {
            Logging.e(TAG, "Failed to get aac decoder");
            ex.printStackTrace();
            return false;
        }
    }

    public long getFilePosition() {
        return this.mExtractor.getSampleTime();
    }

    public void setFilePosition(long pos) {
        this.mExtractor.seekTo(pos, 2);
    }

    public boolean decodeIsReady() {
        return this.mDecodeIsReady;
    }
}
