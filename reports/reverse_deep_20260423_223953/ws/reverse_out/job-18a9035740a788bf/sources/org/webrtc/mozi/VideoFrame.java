package org.webrtc.mozi;

import android.graphics.Matrix;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class VideoFrame implements RefCounted {
    private final Buffer buffer;
    private int colorspace;
    private int extraRotation;
    private final boolean isKeyframe;
    private boolean mirror;
    private final int rotation;
    private final long ssrc;
    private final long timestampNs;

    public interface Buffer extends RefCounted {
        Buffer alignWidth(int i);

        Buffer cropAndScale(int i, int i2, int i3, int i4, int i5, int i6);

        String dump();

        int getHeight();

        int getWidth();

        Buffer mirrorBuffer(boolean z);

        @Override // org.webrtc.mozi.RefCounted
        void release();

        void releaseBy(String str);

        @Override // org.webrtc.mozi.RefCounted
        void retain();

        void retainBy(String str);

        I420Buffer toI420();
    }

    public interface I420Buffer extends Buffer {
        ByteBuffer getDataU();

        ByteBuffer getDataV();

        ByteBuffer getDataY();

        int getStrideU();

        int getStrideV();

        int getStrideY();
    }

    public static class Trace {
        public static final String UNKNOWN = "Unknown";
        private final String name;
        private final List<String> retainTrace = new ArrayList();
        private final List<String> releaseTrace = new ArrayList();

        public Trace(String name) {
            this.name = name;
        }

        public void retain(String trace) {
            synchronized (this.retainTrace) {
                this.retainTrace.add(trace);
            }
        }

        public void release(String trace) {
            synchronized (this.releaseTrace) {
                this.releaseTrace.add(trace);
            }
        }

        public String dump() throws Throwable {
            Throwable th;
            StringBuilder sb = new StringBuilder();
            sb.append("[Name: ");
            sb.append(this.name);
            sb.append("], ");
            sb.append("[retain =>");
            synchronized (this.retainTrace) {
                try {
                    try {
                        int retainSize = this.retainTrace.size();
                        for (String trace : this.retainTrace) {
                            sb.append(trace);
                            sb.append(", ");
                        }
                        sb.append("] ");
                        sb.append("[release => ");
                        synchronized (this.releaseTrace) {
                            try {
                                try {
                                    int releaseSize = this.releaseTrace.size();
                                    for (String trace2 : this.releaseTrace) {
                                        sb.append(trace2);
                                        sb.append(", ");
                                    }
                                    sb.append("] ");
                                    sb.append("[retain size: ");
                                    sb.append(retainSize);
                                    sb.append(", release size: ");
                                    sb.append(releaseSize);
                                    sb.append("] ");
                                    return sb.toString();
                                } catch (Throwable th2) {
                                    th = th2;
                                    throw th;
                                }
                            } catch (Throwable th3) {
                                th = th3;
                                throw th;
                            }
                        }
                    } catch (Throwable th4) {
                        th = th4;
                        throw th;
                    }
                } catch (Throwable th5) {
                    th = th5;
                }
            }
        }
    }

    public interface TextureBuffer extends Buffer {
        int getTextureId();

        int getTextureRotation();

        Matrix getTransformMatrix();

        Type getType();

        void setTextureId(int i);

        void setTypeNative(int i);

        public enum Type {
            OES(36197),
            RGB(3553);

            private final int glTarget;

            Type(int glTarget) {
                this.glTarget = glTarget;
            }

            public int getGlTarget() {
                return this.glTarget;
            }
        }
    }

    public VideoFrame(Buffer buffer, int rotation, long timestampNs) {
        this(buffer, rotation, 0, timestampNs, false, 0L, 0);
    }

    public VideoFrame(Buffer buffer, int rotation, int extraRotation, long timestampNs, boolean isKeyframe, long ssrc, int colorspace) {
        if (buffer == null) {
            throw new IllegalArgumentException("buffer not allowed to be null");
        }
        if (rotation % 90 != 0) {
            throw new IllegalArgumentException("rotation must be a multiple of 90");
        }
        this.buffer = buffer;
        this.rotation = rotation;
        this.extraRotation = extraRotation;
        this.timestampNs = timestampNs;
        this.isKeyframe = isKeyframe;
        this.ssrc = ssrc;
        this.colorspace = colorspace;
        this.mirror = false;
    }

    public VideoFrame(Buffer buffer, int rotation, int extraRotation, long timestampNs, boolean isKeyframe, long ssrc, int colorspace, boolean mirror) {
        if (buffer == null) {
            throw new IllegalArgumentException("buffer not allowed to be null");
        }
        if (rotation % 90 != 0) {
            throw new IllegalArgumentException("rotation must be a multiple of 90");
        }
        this.buffer = buffer;
        this.rotation = rotation;
        this.extraRotation = extraRotation;
        this.timestampNs = timestampNs;
        this.isKeyframe = isKeyframe;
        this.ssrc = ssrc;
        this.colorspace = colorspace;
        this.mirror = mirror;
    }

    public Buffer getBuffer() {
        return this.buffer;
    }

    public int getRotation() {
        return this.rotation;
    }

    public void setExtraRotation(int rotation) {
        this.extraRotation = rotation;
    }

    public int getExtraRotation() {
        return this.extraRotation;
    }

    public long getTimestampNs() {
        return this.timestampNs;
    }

    public int getWidth() {
        return this.buffer.getWidth();
    }

    public int getHeight() {
        return this.buffer.getHeight();
    }

    public int getRotatedWidth() {
        if (this.rotation % JavaScreenCapturer.DEGREE_180 == 0) {
            return this.buffer.getWidth();
        }
        return this.buffer.getHeight();
    }

    public int getRotatedHeight() {
        if (this.rotation % JavaScreenCapturer.DEGREE_180 == 0) {
            return this.buffer.getHeight();
        }
        return this.buffer.getWidth();
    }

    public boolean isKeyframe() {
        return this.isKeyframe;
    }

    public long getSsrc() {
        return this.ssrc;
    }

    public void setColorspace(int colorspace) {
        this.colorspace = colorspace;
    }

    public int getColorspace() {
        return this.colorspace;
    }

    public void setMirror(boolean mirror) {
        this.mirror = mirror;
    }

    public boolean isMirror() {
        return this.mirror;
    }

    @Override // org.webrtc.mozi.RefCounted
    public void retain() {
        retainBy("Unknown");
    }

    @Override // org.webrtc.mozi.RefCounted
    public void release() {
        releaseBy("Unknown");
    }

    public void retainBy(String trace) {
        this.buffer.retainBy(trace);
    }

    public void releaseBy(String trace) {
        this.buffer.releaseBy(trace);
    }

    @Override // org.webrtc.mozi.RefCounted
    public boolean isReleased() {
        return this.buffer.isReleased();
    }

    public String dump() {
        return this.buffer.dump();
    }
}
