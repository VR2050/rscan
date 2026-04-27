package com.ding.rtc;

import com.ding.rtc.DingRtcEngine;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public abstract class DingRtcEngineEventListener {
    public void onJoinChannelResult(int result, String channel, String userId, int elapsed) {
    }

    public void onLeaveChannelResult(int result, DingRtcEngine.DingRtcStats stats) {
    }

    public void onChannelRemainingTimeNotify(int remainingTimeInSec) {
    }

    public void onAudioPublishStateChanged(DingRtcEngine.DingRtcPublishState oldState, DingRtcEngine.DingRtcPublishState newState, int elapseSinceLastState, String channel) {
    }

    public void onVideoPublishStateChanged(DingRtcEngine.DingRtcPublishState oldState, DingRtcEngine.DingRtcPublishState newState, int elapseSinceLastState, String channel) {
    }

    public void onDualStreamPublishStateChanged(DingRtcEngine.DingRtcPublishState oldState, DingRtcEngine.DingRtcPublishState newState, int elapseSinceLastState, String channel) {
    }

    public void onScreenSharePublishStateChanged(DingRtcEngine.DingRtcPublishState oldState, DingRtcEngine.DingRtcPublishState newState, int elapseSinceLastState, String channel) {
    }

    public void onAudioSubscribeStateChanged(String uid, DingRtcEngine.DingRtcSubscribeState oldState, DingRtcEngine.DingRtcSubscribeState newState, int elapseSinceLastState, String channel) {
    }

    public void onVideoSubscribeStateChanged(String uid, DingRtcEngine.DingRtcSubscribeState oldState, DingRtcEngine.DingRtcSubscribeState newState, int elapseSinceLastState, String channel) {
    }

    public void onSubscribeStreamTypeChanged(String uid, DingRtcEngine.DingRtcVideoStreamType oldStreamType, DingRtcEngine.DingRtcVideoStreamType newStreamType, int elapseSinceLastState, String channel) {
    }

    public void onScreenShareSubscribeStateChanged(String uid, DingRtcEngine.DingRtcSubscribeState oldState, DingRtcEngine.DingRtcSubscribeState newState, int elapseSinceLastState, String channel) {
    }

    public void onNetworkQualityChanged(String uid, DingRtcEngine.DingRtcNetworkQuality upQuality, DingRtcEngine.DingRtcNetworkQuality downQuality) {
    }

    public void onOccurWarning(int warn, String message) {
    }

    public void onOccurError(int error, String message) {
    }

    public void onPerformanceLow() {
    }

    public void onPermormanceRecovery() {
    }

    public void onConnectionLost() {
    }

    public void onTryToReconnect() {
    }

    public void onConnectionRecovery() {
    }

    public void onConnectionStatusChanged(DingRtcEngine.DingRtcConnectionStatus status, DingRtcEngine.DingRtcConnectionStatusChangeReason reason) {
    }

    public void onRemoteUserOnLineNotify(String uid, int elapsed) {
    }

    public void onRemoteUserOffLineNotify(String uid, DingRtcEngine.DingRtcUserOfflineReason reason) {
    }

    public void onRemoteTrackAvailableNotify(String uid, DingRtcEngine.DingRtcAudioTrack audioTrack, DingRtcEngine.DingRtcVideoTrack videoTrack) {
    }

    public void onFirstRemoteVideoFrameDrawn(String uid, DingRtcEngine.DingRtcVideoTrack videoTrack, int width, int height, int elapsed) {
    }

    public void onRenderRemoteVideoSizeChanged(String uid, DingRtcEngine.DingRtcVideoTrack videoTrack, int newWidth, int newHeight, int oldWidth, int oldHeight) {
    }

    public void onRenderLocalVideoSizeChanged(DingRtcEngine.DingRtcVideoTrack videoTrack, int newWidth, int newHeight, int oldWidth, int oldHeight) {
    }

    public void onFirstLocalVideoFrameDrawn(int width, int height, int elapsed) {
    }

    public void onFirstVideoFrameReceived(String uid, DingRtcEngine.DingRtcVideoTrack videoTrack, int timeCost) {
    }

    public void onFirstVideoPacketSend(DingRtcEngine.DingRtcVideoTrack videoTrack, int timeCost) {
    }

    public void onFirstAudioPacketSent(String uid, int timeCost) {
    }

    public void onFirstVideoPacketReceived(String uid, DingRtcEngine.DingRtcVideoTrack videoTrack, int timeCost) {
    }

    public void onFirstAudioPacketReceived(String uid, int timeCost) {
    }

    public void onBye(int code) {
    }

    public void onDingRtcStats(DingRtcEngine.DingRtcStats DingRtcStats) {
    }

    public void onUserAudioMuted(String uid, boolean isMute) {
    }

    public void onUserVideoMuted(String uid, boolean isMute, DingRtcEngine.DingRtcVideoTrack track) {
    }

    public void onUserVideoEnabled(String uid, boolean enabled) {
    }

    public void onUserWillResignActive(String uid) {
    }

    public void onUserWillBecomeActive(String uid) {
    }

    public void onUserAudioInterruptedBegin(String uid) {
    }

    public void onUserAudioInterruptedEnded(String uid) {
    }

    public void onMediaRecordEvent(int event, String filePath) {
    }

    public void onRtcLocalVideoStats(DingRtcEngine.DingRtcLocalVideoStats DingRtcStats) {
    }

    public void onRtcRemoteVideoStats(DingRtcEngine.DingRtcRemoteVideoStats DingRtcStats) {
    }

    public void onRtcRemoteAudioStats(DingRtcEngine.DingRtcRemoteAudioStats DingRtcStats) {
    }

    public void onRtcLocalAudioStats(DingRtcEngine.DingRtcLocalAudioStats DingRtcStats) {
    }

    public void onAudioFocusChange(int focusChange) {
    }

    public void onAudioRouteChanged(DingRtcEngine.DingRtcAudioRouteType routing) {
    }

    public void onAudioVolumeIndication(List<DingRtcEngine.DingRtcAudioVolumeInfo> speakers) {
    }

    public void onRecordingDeviceAudioLevel(int level) {
    }

    public void onPlayoutDeviceAudioLevel(int level) {
    }

    public void onAudioPlayoutEnded() {
    }

    public void onAudioDeviceStateChanged(String id, int type, int state) {
    }

    public void onVideoDeviceStateChanged(String id, int type, int state) {
    }

    public void onRemoteVideoResolutionChanged(String uId, DingRtcEngine.DingRtcVideoTrack videoTrack, int oldWidth, int oldHeight, int newWidth, int newHeight) {
    }

    public void onApiCalledExecuted(int error, String api, String result) {
    }

    public void onSnapshotComplete(String uid, DingRtcEngine.DingRtcVideoTrack track, String path, boolean success) {
    }

    public void onMediaExtensionMsgReceived(String uid, byte[] message) {
    }

    public void onAudioMixingStateChanged(DingRtcEngine.DingRtcAudioMixingStatusConfig status) {
    }

    public void onListAllAudioGroups(List<String> groups) {
    }

    public void onAudioGroupJoinResult(int result, String errMsg, String group, List<DingRtcEngine.DingRtcAudioGroupMember> members) {
    }

    public void onAudioGroupLeaveResult(int result, String errMsg, String group) {
    }

    public void onAudioGroupDismissResult(int result, String errMsg, String group) {
    }

    public void onAudioGroupMixResult(String group, boolean mix, int result, String reason) {
    }

    public void onAudioGroupMemberUpdate(int updateOpt, String group, List<DingRtcEngine.DingRtcAudioGroupMember> members) {
    }

    public void onAudioGroupHallMembers(List<DingRtcEngine.DingRtcAudioGroupMember> hallMembers) {
    }

    public void onAudioGroupListUpdate(int updateOpt, String group) {
    }

    public void onGroupNameChanged(String group, String newName) {
    }

    public void onSetGroupNameResult(int result, String errMsg, String group, String groupName) {
    }
}
