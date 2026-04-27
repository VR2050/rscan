package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class VideoResolution {
    public int fps;
    public int height;
    public int width;

    public VideoResolution(int width, int height, int fps) {
        this.width = width;
        this.height = height;
        this.fps = fps;
    }

    public VideoResolution(VideoResolution resolution) {
        if (resolution != null) {
            this.width = resolution.width;
            this.height = resolution.height;
            this.fps = resolution.fps;
        }
    }

    public static boolean equals(VideoResolution v1, VideoResolution v2) {
        return !(v1 == null && v2 == null) && v1 != null && v2 != null && v1.width == v2.width && v1.height == v2.height && v1.fps == v2.fps;
    }

    public String toString() {
        return "VideoResolution{width=" + this.width + ", height=" + this.height + ", fps=" + this.fps + "}";
    }
}
