package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
public abstract class DingRtmClient {

    public static class RtmErrorCode {
        public static final int BAD_SESSION_STATE = -7;
        public static final int INVALID_SESSION_ID = -2;
        public static final int NO_ERROR = 0;
        public static final int RRM_MSG_QUEUE_FULL = -6;
        public static final int RRM_RECEIVER_NOT_EXIST = -8;
        public static final int RRM_SERVICE_ERROR = -4;
        public static final int RRM_SERVICE_NOT_READY = -3;
        public static final int RTM_INNER_ERROR = -1;
        public static final int RTM_MSG_LENGTH_EXCEED = -5;
    }

    public abstract int broadcastData(String sessionId, byte[] data);

    public abstract int closeSession(String sessionId);

    public abstract int joinSession(String sessionId);

    public abstract int leaveSession(String sessionId);

    public abstract int sendData(String sessionId, String toUid, byte[] data);

    public abstract void setListener(DingRtmEventListener listener);

    public enum DingRtmServerState {
        Unavailable(0),
        Available(1);

        private final int state;

        DingRtmServerState(int state) {
            this.state = state;
        }

        public static DingRtmServerState fromValue(int state) {
            for (DingRtmServerState v : values()) {
                if (v.getValue() == state) {
                    return v;
                }
            }
            return null;
        }

        public int getValue() {
            return this.state;
        }
    }
}
