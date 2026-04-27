package org.webrtc.model;

import android.view.SurfaceView;
import java.lang.ref.WeakReference;
import org.webrtc.alirtcInterface.ALI_RTC_INTERFACE;

/* JADX INFO: loaded from: classes3.dex */
public class SophonViewStatus {
    public String callId;
    public boolean flip;
    public int height;
    public boolean isAddDisplayWindow;
    public int renderMode = ALI_RTC_INTERFACE.AliDisplayMode.AliRTCSdk_Auto_Mode.ordinal();
    public WeakReference<SurfaceView> surfaceView;
    public ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videoType;
    public ViewMode viewMode;
    public int width;

    public enum ViewMode {
        LOACALVIEW,
        REMOTEVIEW
    }

    public int getHeight() {
        return this.height;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public int getWidth() {
        return this.width;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public String getCallId() {
        return this.callId;
    }

    public void setCallId(String callId) {
        this.callId = callId;
    }

    public ViewMode getViewMode() {
        return this.viewMode;
    }

    public void setViewMode(ViewMode viewMode) {
        this.viewMode = viewMode;
    }

    public boolean isAddDisplayWindow() {
        return this.isAddDisplayWindow;
    }

    public void setAddDisplayWindow(boolean addDisplayWindow) {
        this.isAddDisplayWindow = addDisplayWindow;
    }

    public ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type getVideoType() {
        return this.videoType;
    }

    public void setVideoType(ALI_RTC_INTERFACE.AliRTCSdk_VideSource_Type videoType) {
        this.videoType = videoType;
    }

    public int getRenderMode() {
        return this.renderMode;
    }

    public void setRenderMode(int renderMode) {
        this.renderMode = renderMode;
    }
}
