package org.webrtc.utils;

import java.text.SimpleDateFormat;
import java.util.Date;
import org.webrtc.alirtcInterface.ALI_RTC_INTERFACE;

/* JADX INFO: loaded from: classes3.dex */
public class AlivcLog {
    private static ALI_RTC_INTERFACE m_nAliRTCInterface;

    public static synchronized void create(ALI_RTC_INTERFACE mAliRTCInterface) {
        m_nAliRTCInterface = mAliRTCInterface;
    }

    public static void enableUpload(boolean enable) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.EnableUpload(enable);
        }
    }

    public static void setUploadAppID(String appID) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.SetUploadAppID(appID);
        }
    }

    public static void setUploadSessionID(String sessionID) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.SetUploadSessionID(sessionID);
        }
    }

    public static void uploadLog() {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UploadLog();
        }
    }

    public static void uploadChannelLog() {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.UploadChannelLog();
        }
    }

    public static void d(String tag, String msg) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Log(_FILE_(), _LINE_(), ALI_RTC_INTERFACE.AliRTCSDKLogLevel.AliRTCSDK_LOG_DEBUG, tag, msg);
        }
    }

    public static void v(String tag, String msg) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Log(_FILE_(), _LINE_(), ALI_RTC_INTERFACE.AliRTCSDKLogLevel.AliRTCSDK_LOG_VERBOSE, tag, msg);
        }
    }

    public static void i(String tag, String msg) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Log(_FILE_(), _LINE_(), ALI_RTC_INTERFACE.AliRTCSDKLogLevel.AliRTCSDK_LOG_INFO, tag, msg);
        }
    }

    public static void w(String tag, String msg) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Log(_FILE_(), _LINE_(), ALI_RTC_INTERFACE.AliRTCSDKLogLevel.AliRTCSDK_LOG_WARNING, tag, msg);
        }
    }

    public static void e(String tag, String msg) {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.Log(_FILE_(), _LINE_(), ALI_RTC_INTERFACE.AliRTCSDKLogLevel.AliRTCSDK_LOG_ERROR, tag, getLineMethod() + msg);
        }
    }

    public static void destroy() {
        ALI_RTC_INTERFACE ali_rtc_interface = m_nAliRTCInterface;
        if (ali_rtc_interface != null) {
            ali_rtc_interface.LogDestroy();
        }
    }

    public static void release() {
        if (m_nAliRTCInterface != null) {
            m_nAliRTCInterface = null;
        }
    }

    private static String getFileLineMethod() {
        StackTraceElement traceElement = new Exception().getStackTrace()[2];
        StringBuffer stringBuffer = new StringBuffer("[");
        stringBuffer.append(traceElement.getFileName());
        stringBuffer.append(" | ");
        stringBuffer.append(traceElement.getLineNumber());
        stringBuffer.append(" | ");
        stringBuffer.append(traceElement.getMethodName());
        StringBuffer toStringBuffer = stringBuffer.append("]");
        return toStringBuffer.toString();
    }

    private static String getLineMethod() {
        StackTraceElement traceElement = new Exception().getStackTrace()[2];
        StringBuffer stringBuffer = new StringBuffer("[");
        stringBuffer.append(traceElement.getLineNumber());
        stringBuffer.append(" | ");
        stringBuffer.append(traceElement.getMethodName());
        StringBuffer toStringBuffer = stringBuffer.append("]");
        return toStringBuffer.toString();
    }

    private static String _FILE_() {
        StackTraceElement traceElement = new Exception().getStackTrace()[2];
        return traceElement.getFileName();
    }

    private static String _FUNC_() {
        StackTraceElement traceElement = new Exception().getStackTrace()[1];
        return traceElement.getMethodName();
    }

    private static int _LINE_() {
        StackTraceElement traceElement = new Exception().getStackTrace()[1];
        return traceElement.getLineNumber();
    }

    private static String _TIME_() {
        Date now = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        return sdf.format(now);
    }
}
