package com.ding.rtc;

import com.ding.rtc.DingRtcEngine;

/* JADX INFO: loaded from: classes.dex */
public class DingRtcRemoteUserInfo {
    public String callID;
    public DingRtcEngine.DingRtcVideoCanvas cameraCanvas;
    public String displayName;
    public boolean hasAudio;
    public boolean hasCamera;
    public boolean hasCameraView;
    public boolean hasScreenSharing;
    public boolean hasScreenView;
    public boolean isOnline;
    public String preferCameraType;
    public boolean requestAudio;
    public boolean requestCamera;
    public boolean requestScreenSharing;
    public DingRtcEngine.DingRtcVideoCanvas screenCanvas;
    public String sessionID;
    public boolean subScribedAudio;
    public String subScribedCameraType;
    public boolean subScribedScreenSharing;
    public String userID;

    private DingRtcRemoteUserInfo() {
    }

    public String getUserID() {
        return this.userID;
    }

    void setUserID(String userID) {
        this.userID = userID;
    }

    public String getSessionID() {
        return this.sessionID;
    }

    void setSessionID(String sessionID) {
        this.sessionID = sessionID;
    }

    public String getCallID() {
        return this.callID;
    }

    void setCallID(String callID) {
        this.callID = callID;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public DingRtcEngine.DingRtcVideoCanvas getCameraCanvas() {
        return this.cameraCanvas;
    }

    void setCameraCanvas(DingRtcEngine.DingRtcVideoCanvas cameraCanvas) {
        this.cameraCanvas = cameraCanvas;
    }

    public DingRtcEngine.DingRtcVideoCanvas getScreenCanvas() {
        return this.screenCanvas;
    }

    void setScreenCanvas(DingRtcEngine.DingRtcVideoCanvas screenCanvas) {
        this.screenCanvas = screenCanvas;
    }

    public boolean isOnline() {
        return this.isOnline;
    }

    void setOnline(boolean online) {
        this.isOnline = online;
    }

    public boolean isHasAudio() {
        return this.hasAudio;
    }

    void setHasAudio(boolean has) {
        this.hasAudio = has;
    }

    public boolean isHasCamera() {
        return this.hasCamera;
    }

    void setHasCamera(boolean has) {
        this.hasCamera = has;
    }

    public boolean isHasScreenSharing() {
        return this.hasScreenSharing;
    }

    void setHasScreenSharing(boolean has) {
        this.hasScreenSharing = has;
    }

    void setSubscribedAudio(boolean sub) {
        this.subScribedAudio = sub;
    }

    public boolean isSubscribedAudio() {
        return this.subScribedAudio;
    }

    void setSubscribedCameraType(String type) {
        this.subScribedCameraType = type;
    }

    public String getSubscribedCameraType() {
        return this.subScribedCameraType;
    }

    void setSubScreenSharing(boolean sub) {
        this.subScribedScreenSharing = sub;
    }

    public boolean isSubscribedScreenSharing() {
        return this.subScribedScreenSharing;
    }

    void setRequestAudio(boolean request) {
        this.requestAudio = request;
    }

    public boolean isRequestAudio() {
        return this.requestAudio;
    }

    void setRequestCamera(boolean request) {
        this.requestCamera = request;
    }

    public boolean isRequestCamera() {
        return this.requestCamera;
    }

    void setRequestScreenSharing(boolean request) {
        this.requestScreenSharing = request;
    }

    public boolean isRequestScreenSharing() {
        return this.requestScreenSharing;
    }

    public String getPreferCameraType() {
        return this.preferCameraType;
    }

    void setPreferCameraType(String type) {
        this.preferCameraType = type;
    }

    public boolean isHasCameraView() {
        return this.hasCameraView;
    }

    void setHasCameraView(boolean hasCameraView) {
        this.hasCameraView = hasCameraView;
    }

    public boolean isHasScreenView() {
        return this.hasScreenView;
    }

    void setHasScreenView(boolean hasScreenView) {
        this.hasScreenView = hasScreenView;
    }

    public String toString() {
        return "DingRtcRemoteUserInfo{userID='" + this.userID + "', sessionID='" + this.sessionID + "', callID='" + this.callID + "', displayName='" + this.displayName + "', isOnline=" + this.isOnline + ", cameraCanvas=" + this.cameraCanvas + ", screenCanvas=" + this.screenCanvas + ", hasAudio=" + this.hasAudio + ", hasCamera=" + this.hasCamera + ", hasScreenSharing=" + this.hasScreenSharing + ", subScribedAudio=" + this.subScribedAudio + ", subScribedCameraType=" + this.subScribedCameraType + ", subScribedScreenSharing=" + this.subScribedScreenSharing + ", requestAudio=" + this.requestAudio + ", requestCamera=" + this.requestCamera + ", requestScreenSharing=" + this.requestScreenSharing + ", preferCameraType=" + this.preferCameraType + ", hasCameraView=" + this.hasCameraView + ", hasScreenView=" + this.hasScreenView + '}';
    }
}
