package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class FpsKeeper {
    public static final long kNumNanosecsPerSec = 1000000000;
    public boolean drop_active_ = false;
    public int max_framerate_request_ = 0;
    public int input_framerate_ = 0;
    public long next_frame_timestamp_ns_ = 0;

    public void SetTargetFps(int fps) {
        synchronized (this) {
            this.drop_active_ = fps < this.input_framerate_;
            this.max_framerate_request_ = fps;
        }
    }

    public void SetInputFps(int fps) {
        synchronized (this) {
            this.drop_active_ = fps > this.max_framerate_request_;
            this.input_framerate_ = fps;
        }
    }

    public int GetOutputFps() {
        int i;
        synchronized (this) {
            i = this.drop_active_ ? this.max_framerate_request_ : this.input_framerate_;
        }
        return i;
    }

    public boolean KeepIt(long in_timestamp_ns) {
        synchronized (this) {
            if (this.max_framerate_request_ <= 0) {
                return false;
            }
            if (!this.drop_active_) {
                return true;
            }
            long frame_interval_ns = 1000000000 / ((long) this.max_framerate_request_);
            if (frame_interval_ns <= 0) {
                return true;
            }
            if (this.next_frame_timestamp_ns_ > 0) {
                long time_until_next_frame_ns = this.next_frame_timestamp_ns_ - in_timestamp_ns;
                if (Math.abs(time_until_next_frame_ns) < frame_interval_ns * 2) {
                    if (time_until_next_frame_ns > 0) {
                        return false;
                    }
                    this.next_frame_timestamp_ns_ += frame_interval_ns;
                    return true;
                }
            }
            this.next_frame_timestamp_ns_ = in_timestamp_ns + (frame_interval_ns / 2);
            return true;
        }
    }
}
