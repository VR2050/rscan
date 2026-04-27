package com.ding.rtc.api;

import java.util.List;
import org.webrtc.mozi.ScreenAudioCapturer;

/* JADX INFO: loaded from: classes.dex */
public class DingRtcWhiteBoardTypes {

    public static class DingRtcWBDocContents {
        public String name;
        public String transDocId;
        public DingRtcWBDocType type = DingRtcWBDocType.NORMAL;
        public List<String> urls;
    }

    public static class DingRtcWBDocExtContents {
        public int height;
        public String name;
        public int totalPages = 1;
        public int width;
    }

    public enum DingRtcWBServerState {
        Unavailable(0),
        Available(1);

        private final int value;

        DingRtcWBServerState(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBServerState fromValue(int value) {
            try {
                DingRtcWBServerState ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBServerState ret2 = Unavailable;
                return ret2;
            }
        }
    }

    public enum DingRtcWBRoleType {
        ADMIN(0),
        ATTENDEE(1),
        VIEWER(2);

        private final int value;

        DingRtcWBRoleType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBRoleType fromValue(int value) {
            try {
                DingRtcWBRoleType ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBRoleType ret2 = ADMIN;
                return ret2;
            }
        }
    }

    public enum DingRtcWBToolType {
        NONE(0),
        SELECT(1),
        CLICK(2),
        HAND(3),
        PATH(4),
        LINE(5),
        RECT(6),
        ELLIPSE(7),
        IMAGE(8),
        TEXT(9),
        DELETER(10),
        BRUSH(11),
        ARROW(12),
        POLYLINE(13),
        POLYGON(14),
        ARC(15),
        CURVE(16),
        LASER(17),
        STAMP(18),
        VANISHPEN(19),
        HIGHLIGHTER(20),
        ERASER(21);

        private final int value;

        DingRtcWBToolType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBToolType fromValue(int value) {
            try {
                DingRtcWBToolType ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBToolType ret2 = NONE;
                return ret2;
            }
        }
    }

    public enum DingRtcWBFillType {
        NONE(0),
        COLOR(1),
        BORDER_FILL(2);

        private final int value;

        DingRtcWBFillType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBFillType fromValue(int value) {
            try {
                DingRtcWBFillType ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBFillType ret2 = NONE;
                return ret2;
            }
        }
    }

    public enum DingRtcWBFontStyle {
        NORMAL(0),
        BOLD(1),
        ITALIC(2),
        BOLD_ITALIC(3);

        private final int value;

        DingRtcWBFontStyle(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBFontStyle fromValue(int value) {
            try {
                DingRtcWBFontStyle ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBFontStyle ret2 = NORMAL;
                return ret2;
            }
        }
    }

    public enum DingRtcWBScalingMode {
        FIT(0),
        CropFill(1),
        CenterCrop(2),
        StretchFill(3);

        private final int value;

        DingRtcWBScalingMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBScalingMode fromValue(int value) {
            try {
                DingRtcWBScalingMode ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBScalingMode ret2 = FIT;
                return ret2;
            }
        }
    }

    public enum DingRtcWBDocType {
        NORMAL(1),
        PDF(3),
        EXTERNAL(5);

        private final int value;

        DingRtcWBDocType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBDocType fromValue(int value) {
            try {
                DingRtcWBDocType ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBDocType ret2 = NORMAL;
                return ret2;
            }
        }
    }

    public enum DingRtcWBDrawEvent {
        DRAW_UNKNOWN(1),
        DRAW_START(2),
        DRAW_END(3),
        DRAW_CANCEL(4),
        SELECT_MOVE_START(5),
        SELECT_MOVE_END(6),
        DELETE_START(7),
        DELETE_END(8),
        TEXT_DRAW(9),
        TEXT_UPDATE(10);

        private final int value;

        DingRtcWBDrawEvent(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBDrawEvent fromValue(int value) {
            try {
                DingRtcWBDrawEvent ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBDrawEvent ret2 = DRAW_UNKNOWN;
                return ret2;
            }
        }
    }

    public enum DingRtcWBContentUpdateType {
        UNKNOWN(1),
        REMOTE_DRAW(2);

        private final int value;

        DingRtcWBContentUpdateType(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBContentUpdateType fromValue(int value) {
            try {
                DingRtcWBContentUpdateType ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBContentUpdateType ret2 = UNKNOWN;
                return ret2;
            }
        }
    }

    public enum DingRtcWBOption {
        ENABLE_UI_RESPONSE(2),
        ENABLE_SHOW_DRAWS(3),
        ENABLE_SCALE_MOVE(4),
        ENABLE_AUTO_SELECTED(5),
        ENABLE_CURSORPOS_SYNC(6),
        ENABLE_SHOW_REMOTE_CURSOR(7),
        ENABLE_LOCAL_CURSOR_LABEL(9),
        ENABLE_SELECT_SHOW_NAME(10),
        ENABLE_TOUCH_SCREEN(11),
        ENABLE_LASER_TRAIL(12),
        ENABLE_ERASE_TRAIL(13),
        ENABLE_RENDER_THREAD(14),
        HOT_ZONE_SIZE(15),
        TOUCH_CURSOR_SIZE(16),
        ENABLE_PALM_ERASER(17),
        ERASER_ZONE_SIZE(18),
        TOUCH_CONFIG(19);

        private final int value;

        DingRtcWBOption(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBOption fromValue(int value) {
            try {
                DingRtcWBOption ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBOption ret2 = ENABLE_UI_RESPONSE;
                return ret2;
            }
        }
    }

    public enum DingRtcWBClearMode {
        ALL(0),
        OTHERS(1),
        SELF(2),
        SPECIFIC(3);

        private final int value;

        DingRtcWBClearMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBClearMode fromValue(int value) {
            try {
                DingRtcWBClearMode ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBClearMode ret2 = ALL;
                return ret2;
            }
        }
    }

    public enum DingRtcWBSnapshotMode {
        VIEW(0),
        ALL(1);

        private final int value;

        DingRtcWBSnapshotMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBSnapshotMode fromValue(int value) {
            try {
                DingRtcWBSnapshotMode ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBSnapshotMode ret2 = VIEW;
                return ret2;
            }
        }
    }

    public enum DingRtcWBImageState {
        LOAD_START(0),
        LOAD_COMPLETE(1),
        LOAD_FAIL(2);

        private final int value;

        DingRtcWBImageState(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBImageState fromValue(int value) {
            try {
                DingRtcWBImageState ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBImageState ret2 = LOAD_START;
                return ret2;
            }
        }
    }

    public enum DingRtcWBFileTransState {
        TRANSCODE_START(0),
        TRANSCODE_COMPLETE(1),
        TRANSCODE_FAIL(2),
        TRANSCODE_START_FAIL(3),
        TRANSCODE_QUERY_FAIL(4);

        private final int value;

        DingRtcWBFileTransState(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBFileTransState fromValue(int value) {
            try {
                DingRtcWBFileTransState ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBFileTransState ret2 = TRANSCODE_START;
                return ret2;
            }
        }
    }

    public static class DingRtcWBColor {
        public float a;
        public float b;
        public float g;
        public float r;

        public DingRtcWBColor(float r, float g, float b, float a) {
            this.r = 0.0f;
            this.g = 0.0f;
            this.b = 0.0f;
            this.a = 1.0f;
            this.r = r;
            this.g = g;
            this.b = b;
            this.a = a;
        }
    }

    public static class DingRtcWBClearParam {
        public boolean curPage;
        public DingRtcWBClearMode mode;

        public DingRtcWBClearParam(boolean curPage, DingRtcWBClearMode mode) {
            this.curPage = true;
            this.curPage = curPage;
            this.mode = mode;
        }
    }

    public enum DingRtcWBMode {
        BASIC(0),
        ADVANCE(1);

        private final int value;

        DingRtcWBMode(int value) {
            this.value = value;
        }

        public int getValue() {
            return this.value;
        }

        public static DingRtcWBMode fromValue(int value) {
            try {
                DingRtcWBMode ret = values()[value];
                return ret;
            } catch (Exception e) {
                DingRtcWBMode ret2 = BASIC;
                return ret2;
            }
        }
    }

    public enum ErrorCode {
        OK(0),
        FAILED(-1),
        FATAL(-2),
        INVALID_ARGS(-3),
        INVALID_STATE(-4),
        INVALID_INDEX(-5),
        ALREADY_EXIST(-6),
        NOT_EXIST(-7),
        NOT_FOUND(-8),
        NOT_SUPPORTED(-9),
        NOT_IMPLEMENTED(-10),
        NOT_INITIALIZED(-11),
        LIMIT_REACHED(-12),
        NO_PRIVILEGE(-13),
        IN_PROGRESS(-14),
        WRONG_THREAD(-15),
        TIMEOUT(-16),
        ABORTED(-17),
        TOO_MANY_OPS(-18),
        OUT_OF_MEMORY(-19),
        OUT_OF_DISK_SPACE(-20),
        AUTH_FAILED(-101),
        USER_REJECTED(ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_EXCEPTION),
        USER_EXPELED(ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_STATE_MISMATCH),
        USER_DUPLICATE(ScreenAudioCapturer.ERROR_AUDIO_RECORD_START_EXCEPTION),
        CHANNEL_CLOSED(-151),
        CHANNEL_FULL(-152),
        CHANNEL_LOCKED(-153),
        CHANNEL_MODE(-154),
        CHANNEL_CRYPTOTYPE(-155),
        GROUP_DISMISSED(-190),
        NETWORK_ERROR(-301),
        DEVICE_OCCUPIED(-401);

        private int value;

        ErrorCode(int v) {
            this.value = v;
        }

        public int getValue() {
            return this.value;
        }

        public static ErrorCode cast(int v) {
            for (ErrorCode r : values()) {
                if (r.value == v) {
                    return r;
                }
            }
            return FATAL;
        }
    }

    public static class DingRtcWBConfig {
        public int height;
        public DingRtcWBMode mode;
        public int width;

        public DingRtcWBConfig(int width, int height, DingRtcWBMode mode) {
            this.width = width;
            this.height = height;
            this.mode = mode;
        }
    }

    public static class DingRtcWBStamp {
        public boolean resizable;
        public String stampId;
        public String stampPath;

        public DingRtcWBStamp(String stampId, String stampPath, boolean resizable) {
            this.stampId = stampId;
            this.stampPath = stampPath;
            this.resizable = resizable;
        }
    }

    public static class DingRtcWBUserMember {
        public String uid;

        public DingRtcWBUserMember(String uid) {
            this.uid = uid;
        }
    }

    public static class DingRtcWBGestureConfig {
        public int minMoveSpan = 5;
        public int minScaleSpan = 20;
        public int minScrollSpan = 10;
        public boolean palmEnabled = false;

        @Deprecated
        public float palmDetectLevel_0 = 0.018f;
        public float palmDetectLevel0 = 0.0f;

        @Deprecated
        public float palmDetectLevel_1 = 0.038f;
        public float palmDetectLevel1 = 0.0f;

        @Deprecated
        public float palmSizeLevel_0 = 45.0f;
        public float palmSizeLevel0 = 0.0f;

        @Deprecated
        public float palmSizeLevel_1 = 90.0f;
        public float palmSizeLevel1 = 0.0f;

        public float getPalmDetectLevel0() {
            if (this.palmDetectLevel0 == 0.0f) {
                float f = this.palmDetectLevel_0;
                if (f != 0.0f) {
                    this.palmDetectLevel0 = f;
                }
            }
            return this.palmDetectLevel0;
        }

        public float getPalmDetectLevel1() {
            if (this.palmDetectLevel1 == 0.0f) {
                float f = this.palmDetectLevel_1;
                if (f != 0.0f) {
                    this.palmDetectLevel1 = f;
                }
            }
            return this.palmDetectLevel1;
        }

        public float getPalmSizeLevel0() {
            if (this.palmSizeLevel0 == 0.0f) {
                float f = this.palmSizeLevel_0;
                if (f != 0.0f) {
                    this.palmSizeLevel0 = f;
                }
            }
            return this.palmSizeLevel0;
        }

        public float getPalmSizeLevel1() {
            if (this.palmSizeLevel1 == 0.0f) {
                float f = this.palmSizeLevel_1;
                if (f != 0.0f) {
                    this.palmSizeLevel1 = f;
                }
            }
            return this.palmSizeLevel1;
        }

        public String toString() {
            return "WBGestureConfig{minMoveSpan=" + this.minMoveSpan + ", minScaleSpan=" + this.minScaleSpan + ", minScrollSpan=" + this.minScrollSpan + ", palmEnabled=" + this.palmEnabled + ", palmDetectLevel_0=" + getPalmDetectLevel0() + ", palmDetectLevel_1=" + getPalmDetectLevel1() + ", palmSizeLevel_0=" + getPalmSizeLevel0() + ", palmSizeLevel_1=" + getPalmSizeLevel1() + '}';
        }
    }
}
