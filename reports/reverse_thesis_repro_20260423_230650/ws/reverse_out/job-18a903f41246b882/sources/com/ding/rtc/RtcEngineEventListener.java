package com.ding.rtc;

import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.model.AudioGroupMember;
import com.ding.rtc.model.AudioMixingStats;
import com.ding.rtc.model.AudioVolumeInfo;
import com.ding.rtc.model.LocalAudioStats;
import com.ding.rtc.model.LocalVideoStats;
import com.ding.rtc.model.RemoteAudioStats;
import com.ding.rtc.model.RemoteVideoStats;
import com.ding.rtc.model.RtcEngineStats;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
class RtcEngineEventListener {
    private final Object mEngineListenerLock = new Object();
    private DingRtcEngineEventListener mRtcEngineEventListener;

    RtcEngineEventListener() {
    }

    public void setRtcEngineEventListener(DingRtcEngineEventListener listener) {
        synchronized (this.mEngineListenerLock) {
            this.mRtcEngineEventListener = listener;
        }
    }

    private void onJoinChannelResult(int result, String channel, String userId, int elapsed) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onJoinChannelResult(result, channel, userId, elapsed);
            }
        }
    }

    private void onLeaveChannelResult(int result, RtcEngineStats stats) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onLeaveChannelResult(result, stats.convert());
            }
        }
    }

    private void onChannelRemainingTimeNotify(int remainingTimeInSec) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onChannelRemainingTimeNotify(remainingTimeInSec);
            }
        }
    }

    private void OnRemoteUserOnLineNotify(String uid, int elapsed) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onRemoteUserOnLineNotify(uid, elapsed);
            }
        }
    }

    private void onRemoteUserOffLineNotify(String uid, int reason) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcUserOfflineReason offlineReason = DingRtcEngine.DingRtcUserOfflineReason.fromValue(reason);
                this.mRtcEngineEventListener.onRemoteUserOffLineNotify(uid, offlineReason);
            }
        }
    }

    private void onBye(int code) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onBye(code);
            }
        }
    }

    private void onStatisticsLog(String log) {
        synchronized (this.mEngineListenerLock) {
        }
    }

    private void onOccurWarning(int warn, String msg) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onOccurWarning(warn, msg);
            }
        }
    }

    private void onOccurError(int error, String msg) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onOccurError(error, msg);
            }
        }
    }

    private void onStatisticsLevelLog(int level, String log) {
        synchronized (this.mEngineListenerLock) {
        }
    }

    private void onLocalAudioStats(LocalAudioStats stats) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onRtcLocalAudioStats(stats.convert());
            }
        }
    }

    void onLocalVideoStats(LocalVideoStats stats) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onRtcLocalVideoStats(stats.convert());
            }
        }
    }

    private void onRemoteAudioStats(RemoteAudioStats stats) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onRtcRemoteAudioStats(stats.convert());
            }
        }
    }

    void onRemoteVideoStats(RemoteVideoStats stats) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onRtcRemoteVideoStats(stats.convert());
            }
        }
    }

    void onStats(RtcEngineStats stats) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onDingRtcStats(stats.convert());
            }
        }
    }

    private void onAudioPublishStateChanged(int oldState, int newState, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcPublishState old_state = DingRtcEngine.DingRtcPublishState.fromValue(oldState);
                DingRtcEngine.DingRtcPublishState new_state = DingRtcEngine.DingRtcPublishState.fromValue(newState);
                this.mRtcEngineEventListener.onAudioPublishStateChanged(old_state, new_state, elapseSinceLastState, channel);
            }
        }
    }

    private void onVideoPublishStateChanged(int oldState, int newState, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcPublishState old_state = DingRtcEngine.DingRtcPublishState.fromValue(oldState);
                DingRtcEngine.DingRtcPublishState new_state = DingRtcEngine.DingRtcPublishState.fromValue(newState);
                this.mRtcEngineEventListener.onVideoPublishStateChanged(old_state, new_state, elapseSinceLastState, channel);
            }
        }
    }

    private void onScreenSharePublishStateChanged(int oldState, int newState, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcPublishState old_state = DingRtcEngine.DingRtcPublishState.fromValue(oldState);
                DingRtcEngine.DingRtcPublishState new_state = DingRtcEngine.DingRtcPublishState.fromValue(newState);
                this.mRtcEngineEventListener.onScreenSharePublishStateChanged(old_state, new_state, elapseSinceLastState, channel);
            }
        }
    }

    private void onRemoteTrackAvailableNotify(String uid, int audioTrack, int videoTrack) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcAudioTrack atrack = DingRtcEngine.DingRtcAudioTrack.fromValue(audioTrack);
                DingRtcEngine.DingRtcVideoTrack vtrack = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onRemoteTrackAvailableNotify(uid, atrack, vtrack);
            }
        }
    }

    private void onUserAudioMuted(String uid, boolean isMute) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onUserAudioMuted(uid, isMute);
            }
        }
    }

    private void onUserVideoMuted(String uid, boolean isMute, int videoTrack) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onUserVideoMuted(uid, isMute, track);
            }
        }
    }

    private void onUserVideoEnabled(String uid, boolean enabled) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onUserVideoEnabled(uid, enabled);
            }
        }
    }

    private void onUserWillResignActive(String uid) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onUserWillResignActive(uid);
            }
        }
    }

    private void onUserWillBecomeActive(String uid) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onUserWillBecomeActive(uid);
            }
        }
    }

    private void onUserAudioInterruptedBegin(String uid) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onUserAudioInterruptedBegin(uid);
            }
        }
    }

    private void onUserAudioInterruptedEnded(String uid) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onUserAudioInterruptedEnded(uid);
            }
        }
    }

    private void onFirstRemoteVideoFrameDrawn(String uid, int videoTrack, int width, int height, int elapsed) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onFirstRemoteVideoFrameDrawn(uid, track, width, height, elapsed);
            }
        }
    }

    private void onRenderRemoteVideoSizeChanged(String uid, int videoTrack, int newWidth, int newHeight, int oldWidth, int oldHeight) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onRenderRemoteVideoSizeChanged(uid, track, newWidth, newHeight, oldWidth, oldHeight);
            }
        }
    }

    private void onRenderLocalVideoSizeChanged(int videoTrack, int newWidth, int newHeight, int oldWidth, int oldHeight) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onRenderLocalVideoSizeChanged(track, newWidth, newHeight, oldWidth, oldHeight);
            }
        }
    }

    private void OnFirstVideoPacketSend(int videoTrack, int timeCost) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onFirstVideoPacketSend(track, timeCost);
            }
        }
    }

    private void OnFirstVideoPacketReceived(String uid, int videoTrack, int timeCost) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onFirstVideoPacketReceived(uid, track, timeCost);
            }
        }
    }

    void OnFirstVideoFrameReceived(String uid, int videoTrack, int timeCost) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoTrack track = DingRtcEngine.DingRtcVideoTrack.fromValue(videoTrack);
                this.mRtcEngineEventListener.onFirstVideoFrameReceived(uid, track, timeCost);
            }
        }
    }

    private void onFirstLocalVideoFrameDrawn(int width, int height, int elapsed) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onFirstLocalVideoFrameDrawn(width, height, elapsed);
            }
        }
    }

    private void onFirstAudioPacketSent(String uid, int timeCost) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onFirstAudioPacketSent(uid, timeCost);
            }
        }
    }

    private void onFirstAudioPacketReceived(String uid, int timeCost) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onFirstAudioPacketReceived(uid, timeCost);
            }
        }
    }

    private void onAudioSubscribeStateChanged(String uid, int oldState, int newState, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcSubscribeState old_state = DingRtcEngine.DingRtcSubscribeState.fromValue(oldState);
                DingRtcEngine.DingRtcSubscribeState new_state = DingRtcEngine.DingRtcSubscribeState.fromValue(newState);
                this.mRtcEngineEventListener.onAudioSubscribeStateChanged(uid, old_state, new_state, elapseSinceLastState, channel);
            }
        }
    }

    private void onVideoSubscribeStateChanged(String uid, int oldState, int newState, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcSubscribeState old_state = DingRtcEngine.DingRtcSubscribeState.fromValue(oldState);
                DingRtcEngine.DingRtcSubscribeState new_state = DingRtcEngine.DingRtcSubscribeState.fromValue(newState);
                this.mRtcEngineEventListener.onVideoSubscribeStateChanged(uid, old_state, new_state, elapseSinceLastState, channel);
            }
        }
    }

    private void onScreenShareSubscribeStateChanged(String uid, int oldState, int newState, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcSubscribeState old_state = DingRtcEngine.DingRtcSubscribeState.fromValue(oldState);
                DingRtcEngine.DingRtcSubscribeState new_state = DingRtcEngine.DingRtcSubscribeState.fromValue(newState);
                this.mRtcEngineEventListener.onScreenShareSubscribeStateChanged(uid, old_state, new_state, elapseSinceLastState, channel);
            }
        }
    }

    private void onSubscribeStreamTypeChanged(String uid, int oldStreamType, int newStreamType, int elapseSinceLastState, String channel) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                DingRtcEngine.DingRtcVideoStreamType oldType = DingRtcEngine.DingRtcVideoStreamType.fromValue(oldStreamType);
                DingRtcEngine.DingRtcVideoStreamType newType = DingRtcEngine.DingRtcVideoStreamType.fromValue(newStreamType);
                this.mRtcEngineEventListener.onSubscribeStreamTypeChanged(uid, oldType, newType, elapseSinceLastState, channel);
            }
        }
    }

    private void onRecordingDeviceAudioLevel(int level) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onRecordingDeviceAudioLevel(level);
            }
        }
    }

    private void onPlayoutDeviceAudioLevel(int level) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onPlayoutDeviceAudioLevel(level);
            }
        }
    }

    private void onAudioPlayoutEnded() {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioPlayoutEnded();
            }
        }
    }

    private void onAudioDeviceStateChanged(String id, int type, int state) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioDeviceStateChanged(id, type, state);
            }
        }
    }

    private void onVideoDeviceStateChanged(String id, int type, int state) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onVideoDeviceStateChanged(id, type, state);
            }
        }
    }

    private void onApiCalledExecuted(int error, String api, String result) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onApiCalledExecuted(error, api, result);
            }
        }
    }

    private void onAudioRouteChanged(int audioRouteType) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioRouteChanged(DingRtcEngine.DingRtcAudioRouteType.fromValue(audioRouteType));
            }
        }
    }

    private void onAudioFocusChanged(int audioFocusChange) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioFocusChange(audioFocusChange);
            }
        }
    }

    private void onAudioVolumeIndication(AudioVolumeInfo[] speakers, int speakerNumber) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null && speakers != null && speakerNumber > 0) {
                ArrayList<DingRtcEngine.DingRtcAudioVolumeInfo> user_info = new ArrayList<>();
                for (AudioVolumeInfo audioVolumeInfo : speakers) {
                    user_info.add(audioVolumeInfo.convert());
                }
                this.mRtcEngineEventListener.onAudioVolumeIndication(user_info);
            }
        }
    }

    private void onConnectionStatusChanged(int status, int reason) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onConnectionStatusChanged(DingRtcEngine.DingRtcConnectionStatus.getDingRtcConnectionStatus(status), DingRtcEngine.DingRtcConnectionStatusChangeReason.getConnectionStatusChangeReason(reason));
            }
        }
    }

    private void onNetworkQualityChanged(String uid, int upQuality, int downQuality) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onNetworkQualityChanged(uid, DingRtcEngine.DingRtcNetworkQuality.getQuality(upQuality), DingRtcEngine.DingRtcNetworkQuality.getQuality(downQuality));
            }
        }
    }

    public void onSnapshotComplete(String uid, int track, String path, int width, int height) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null && path != null && width != 0 && height != 0) {
                this.mRtcEngineEventListener.onSnapshotComplete(uid, DingRtcEngine.DingRtcVideoTrack.fromValue(track), path, true);
            } else if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onSnapshotComplete(uid, DingRtcEngine.DingRtcVideoTrack.fromValue(track), path, false);
            }
        }
    }

    public void onMediaExtensionMsgReceived(String uid, byte[] message) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onMediaExtensionMsgReceived(uid, message);
            }
        }
    }

    public void onAudioMixingStateChanged(AudioMixingStats status) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null && status != null) {
                this.mRtcEngineEventListener.onAudioMixingStateChanged(status.convert());
            }
        }
    }

    public void onListAllAudioGroups(String[] groups) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                List<String> groupList = new ArrayList<>();
                if (groups != null && groups.length > 0) {
                    groupList.addAll(Arrays.asList(groups));
                }
                this.mRtcEngineEventListener.onListAllAudioGroups(groupList);
            }
        }
    }

    public void onAudioGroupJoinResult(int result, String errMsg, String group, AudioGroupMember[] members) {
        if (this.mRtcEngineEventListener != null) {
            List<DingRtcEngine.DingRtcAudioGroupMember> memberList = new ArrayList<>();
            if (members != null && members.length > 0) {
                for (AudioGroupMember member : members) {
                    memberList.add(member.convert());
                }
            }
            this.mRtcEngineEventListener.onAudioGroupJoinResult(result, errMsg, group, memberList);
        }
    }

    public void onAudioGroupLeaveResult(int result, String errMsg, String group) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioGroupLeaveResult(result, errMsg, group);
            }
        }
    }

    public void onAudioGroupDismissResult(int result, String errMsg, String group) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioGroupDismissResult(result, errMsg, group);
            }
        }
    }

    public void onAudioGroupMixResult(String group, boolean mix, int result, String reason) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioGroupMixResult(group, mix, result, reason);
            }
        }
    }

    public void onAudioGroupMemberUpdate(int updateOpt, String group, AudioGroupMember[] members) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                List<DingRtcEngine.DingRtcAudioGroupMember> memberList = new ArrayList<>();
                if (members != null && members.length > 0) {
                    for (AudioGroupMember member : members) {
                        memberList.add(member.convert());
                    }
                }
                this.mRtcEngineEventListener.onAudioGroupMemberUpdate(updateOpt, group, memberList);
            }
        }
    }

    public void onAudioGroupHallMembers(AudioGroupMember[] hallMembers) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                List<DingRtcEngine.DingRtcAudioGroupMember> members = new ArrayList<>();
                if (hallMembers != null && hallMembers.length > 0) {
                    for (AudioGroupMember member : hallMembers) {
                        members.add(member.convert());
                    }
                }
                this.mRtcEngineEventListener.onAudioGroupHallMembers(members);
            }
        }
    }

    public void onAudioGroupListUpdate(int updateOpt, String group) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onAudioGroupListUpdate(updateOpt, group);
            }
        }
    }

    public void onGroupNameChanged(String group, String newName) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onGroupNameChanged(group, newName);
            }
        }
    }

    public void onSetGroupNameResult(int result, String errMsg, String group, String groupName) {
        synchronized (this.mEngineListenerLock) {
            if (this.mRtcEngineEventListener != null) {
                this.mRtcEngineEventListener.onSetGroupNameResult(result, errMsg, group, groupName);
            }
        }
    }
}
