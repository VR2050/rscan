package org.webrtc.alirtcInterface;

import android.content.Context;
import java.util.ArrayList;
import java.util.HashMap;
import org.webrtc.alirtcInterface.ALI_RTC_INTERFACE;
import org.webrtc.utils.CpuMonitor;
import org.webrtc.utils.MemoryMonitor;
import org.webrtc.utils.NetworkMonitor;
import org.webrtc.utils.RecvStatsReportParam;

/* JADX INFO: loaded from: classes3.dex */
public class AliSophonEngineImpl implements AliSophonEngine {
    private static final long NETWORK_OBSERVER = 10001;
    private ALI_RTC_INTERFACE aliRtc;
    private CpuMonitor cpuMonitor;
    private MemoryMonitor memoryMonitor;
    private SophonEventListener sophonEventListener;

    AliSophonEngineImpl(Context context, ALI_RTC_INTERFACE aliRtcInterface, SophonEventListener listener) {
        this.sophonEventListener = listener;
        this.aliRtc = aliRtcInterface;
        this.cpuMonitor = new CpuMonitor(context);
        this.memoryMonitor = new MemoryMonitor(context);
        startMonitoring();
        this.cpuMonitor.resume();
        this.memoryMonitor.resume();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onGslbResult(int result) {
        this.sophonEventListener.onGslbResult(result);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onJoinChannelResult(int result) {
        this.sophonEventListener.onJoinChannelResult(result);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onLeaveChannelResult(int result) {
        this.sophonEventListener.onLeaveChannelResult(result);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onPublishResult(int result, String callId) {
        this.sophonEventListener.onPublishResult(result, callId);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onRepublishResult(int result, String callId) {
        this.sophonEventListener.onRepublishResult(result, callId);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onUnpublishResult(int result, String callId) {
        this.sophonEventListener.onUnpublishResult(result, callId);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onSubscribeResult(int result, String callId) {
        this.sophonEventListener.onSubscribeResult(result, callId);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onResubscribeResult(int result, String callId) {
        this.sophonEventListener.onResubscribeResult(result, callId);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onUnsubscribeResult(int result, String callId) {
        this.sophonEventListener.onUnsubscribeResult(result, callId);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onCollectStatus(String callId, HashMap collectStatus) {
        this.sophonEventListener.onCollectStats(callId, collectStatus);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onConnectionChange(int mediaConState) {
        this.sophonEventListener.onConnectionChange(mediaConState);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onWarning(int warningEvent, String params) {
        this.sophonEventListener.onWarning(warningEvent, params);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onError(int event, String params) {
        this.sophonEventListener.onError(event, params);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onLogMessage(String message) {
        this.sophonEventListener.onLogMessage(message);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantPublishNotify(PublisherInfo[] publisherList, int publisherCount) {
        this.sophonEventListener.onParticipantPublishNotify(publisherList, publisherCount);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onSubscribeResult2(int result, String callID, ALI_RTC_INTERFACE.AliSubscribeConfig reqConfig, ALI_RTC_INTERFACE.AliSubscribeConfig curConfig) {
        this.sophonEventListener.onSubscribeResult2(result, callID, reqConfig, curConfig);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onResubscribeResult2(int result, String callID, ALI_RTC_INTERFACE.AliSubscribeConfig reqConfig, ALI_RTC_INTERFACE.AliSubscribeConfig curConfig) {
        this.sophonEventListener.onResubscribeResult2(result, callID, reqConfig, curConfig);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantJoinNotify(AliParticipantInfo[] participantList, int feedCount) {
        this.sophonEventListener.onParticipantJoinNotify(participantList, feedCount);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantLeaveNotify(AliParticipantInfo[] participantList, int feedCount) {
        this.sophonEventListener.onParticipantLeaveNotify(participantList, feedCount);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantSubscribeNotify(AliSubscriberInfo[] subcribeinfoList, int feedCount) {
        this.sophonEventListener.onParticipantSubscribeNotify(subcribeinfoList, feedCount);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantStatusNotify(AliStatusInfo[] status_info_list, int count) {
        this.sophonEventListener.onParticipantStatusNotify(status_info_list, count);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantUnpublishNotify(AliUnPublisherInfo[] unpublisherList, int feedCount) {
        this.sophonEventListener.onParticipantUnpublishNotify(unpublisherList, feedCount);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onParticipantUnsubscribeNotify(AliParticipantInfo[] participantList, int feedCount) {
        this.sophonEventListener.onParticipantUnsubscribeNotify(participantList, feedCount);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onTransportStatusChange(String callId, ALI_RTC_INTERFACE.TransportType event, ALI_RTC_INTERFACE.TransportStatus status) {
        this.sophonEventListener.onTransportStatusChange(callId, event, status);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onNetworkQualityChange(ArrayList<ALI_RTC_INTERFACE.AliTransportInfo> network_quality) {
        this.sophonEventListener.onNetworkQualityChange(network_quality);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onRecvStatsReport(HashMap map) {
        RecvStatsReportParam.generatePublicParamters(map, getCurrentConnectionType(), String.valueOf(((double) this.cpuMonitor.getCpuUsageCurrent()) / 100.0d), String.valueOf(this.memoryMonitor.getMemoryUsageCurrentByPid()), this.aliRtc.GetSDKVersion());
    }

    private void startMonitoring() {
        NetworkMonitor networkMonitor = NetworkMonitor.getInstance();
        networkMonitor.startMonitoring(NETWORK_OBSERVER);
    }

    private void stopMonitoring() {
        NetworkMonitor networkMonitor = NetworkMonitor.getInstance();
        networkMonitor.stopMonitoring(NETWORK_OBSERVER);
    }

    private String getCurrentConnectionType() {
        NetworkMonitor networkMonitor = NetworkMonitor.getInstance();
        return networkMonitor.getCurrentConnectionType().toString();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void release() {
        stopMonitoring();
        this.cpuMonitor.pause();
        this.memoryMonitor.pause();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onUplinkChannelMessage(int result, String contentType, String content) {
        this.sophonEventListener.onUplinkChannelMessage(result, contentType, content);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public String onCollectPlatformProfile() {
        return this.sophonEventListener.onCollectPlatformProfile();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public String onFetchPerformanceInfo() {
        return this.sophonEventListener.onFetchPerformanceInfo();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public boolean onFetchAudioPermissionInfo() {
        return this.sophonEventListener.onFetchAudioPermissionInfo();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public String onFetchAudioDeviceInfo() {
        return this.sophonEventListener.onFetchAudioDeviceInfo();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onWindowRenderReady(String callId, int videoType) {
        this.sophonEventListener.onWindowRenderReady(callId, videoType);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onUpdateRoleNotify(ALI_RTC_INTERFACE.AliRTCSDK_Client_Role old_role, ALI_RTC_INTERFACE.AliRTCSDK_Client_Role new_role) {
        this.sophonEventListener.onUpdateRoleNotify(old_role, new_role);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onFirstFrameReceived(String callId, String stream_label, String track_label, int time_cost_ms) {
        this.sophonEventListener.onFirstFramereceived(callId, stream_label, track_label, time_cost_ms);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onFirstPacketSent(String callId, String stream_label, String track_label, int time_cost_ms) {
        this.sophonEventListener.onFirstPacketSent(callId, stream_label, track_label, time_cost_ms);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onFirstPacketReceived(String callId, String stream_label, String track_label, int time_cost_ms) {
        this.sophonEventListener.onFirstPacketReceived(callId, stream_label, track_label, time_cost_ms);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onBye(int code) {
        this.sophonEventListener.onBye(code);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onMessage(String tid, String contentType, String content) {
        this.sophonEventListener.onMessage(tid, contentType, content);
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public int onFetchDeviceOrientation() {
        return this.sophonEventListener.onFetchDeviceOrientation();
    }

    @Override // org.webrtc.alirtcInterface.AliSophonEngine
    public void onAliRtcStats(ALI_RTC_INTERFACE.AliRtcStats aliRtcStats) {
        this.sophonEventListener.onAliRtcStats(aliRtcStats);
    }
}
