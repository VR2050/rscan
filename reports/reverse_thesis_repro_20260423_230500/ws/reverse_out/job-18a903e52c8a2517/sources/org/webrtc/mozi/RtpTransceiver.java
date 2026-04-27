package org.webrtc.mozi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.webrtc.mozi.MediaStreamTrack;

/* JADX INFO: loaded from: classes3.dex */
public class RtpTransceiver {
    private RtpReceiver cachedReceiver;
    private RtpSender cachedSender;
    private final long nativeRtpTransceiver;

    private static native RtpTransceiverDirection nativeCurrentDirection(long j);

    private static native RtpTransceiverDirection nativeDirection(long j);

    private static native MediaStreamTrack.MediaType nativeGetMediaType(long j);

    private static native String nativeGetMid(long j);

    private static native RtpReceiver nativeGetReceiver(long j);

    private static native RtpSender nativeGetSender(long j);

    private static native void nativeSetDirection(long j, RtpTransceiverDirection rtpTransceiverDirection);

    private static native void nativeStop(long j);

    private static native boolean nativeStopped(long j);

    public enum RtpTransceiverDirection {
        SEND_RECV(0),
        SEND_ONLY(1),
        RECV_ONLY(2),
        INACTIVE(3);

        private final int nativeIndex;

        RtpTransceiverDirection(int nativeIndex) {
            this.nativeIndex = nativeIndex;
        }

        int getNativeIndex() {
            return this.nativeIndex;
        }

        static RtpTransceiverDirection fromNativeIndex(int nativeIndex) {
            for (RtpTransceiverDirection type : values()) {
                if (type.getNativeIndex() == nativeIndex) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Uknown native RtpTransceiverDirection type" + nativeIndex);
        }
    }

    public static final class RtpTransceiverInit {
        private final RtpTransceiverDirection direction;
        private final List<String> streamIds;

        public RtpTransceiverInit() {
            this(RtpTransceiverDirection.SEND_RECV);
        }

        public RtpTransceiverInit(RtpTransceiverDirection direction) {
            this(direction, Collections.emptyList());
        }

        public RtpTransceiverInit(RtpTransceiverDirection direction, List<String> streamIds) {
            this.direction = direction;
            this.streamIds = new ArrayList(streamIds);
        }

        int getDirectionNativeIndex() {
            return this.direction.getNativeIndex();
        }

        List<String> getStreamIds() {
            return new ArrayList(this.streamIds);
        }
    }

    protected RtpTransceiver(long nativeRtpTransceiver) {
        this.nativeRtpTransceiver = nativeRtpTransceiver;
        this.cachedSender = nativeGetSender(nativeRtpTransceiver);
        this.cachedReceiver = nativeGetReceiver(nativeRtpTransceiver);
    }

    public MediaStreamTrack.MediaType getMediaType() {
        return nativeGetMediaType(this.nativeRtpTransceiver);
    }

    public String getMid() {
        return nativeGetMid(this.nativeRtpTransceiver);
    }

    public RtpSender getSender() {
        return this.cachedSender;
    }

    public RtpReceiver getReceiver() {
        return this.cachedReceiver;
    }

    public boolean isStopped() {
        return nativeStopped(this.nativeRtpTransceiver);
    }

    public RtpTransceiverDirection getDirection() {
        return nativeDirection(this.nativeRtpTransceiver);
    }

    public RtpTransceiverDirection getCurrentDirection() {
        return nativeCurrentDirection(this.nativeRtpTransceiver);
    }

    public void setDirection(RtpTransceiverDirection rtpTransceiverDirection) {
        nativeSetDirection(this.nativeRtpTransceiver, rtpTransceiverDirection);
    }

    public void stop() {
        nativeStop(this.nativeRtpTransceiver);
    }

    public void dispose() {
        this.cachedSender.dispose();
        this.cachedReceiver.dispose();
        JniCommon.nativeReleaseRef(this.nativeRtpTransceiver);
    }
}
