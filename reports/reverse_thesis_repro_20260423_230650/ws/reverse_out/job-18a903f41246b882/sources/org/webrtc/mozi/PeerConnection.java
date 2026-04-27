package org.webrtc.mozi;

import com.king.zxing.util.LogUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.webrtc.mozi.DataChannel;
import org.webrtc.mozi.MediaStreamTrack;
import org.webrtc.mozi.RtpTransceiver;

/* JADX INFO: loaded from: classes3.dex */
public class PeerConnection {
    private static final String TAG = "PeerConnection";
    private final List<MediaStream> localStreams;
    private long nativeOwtFactory;
    private final long nativePeerConnection;
    private List<RtpReceiver> receivers;
    private List<RtpSender> senders;
    private List<RtpTransceiver> transceivers;

    public enum AdapterType {
        UNKNOWN,
        ETHERNET,
        WIFI,
        CELLULAR,
        VPN,
        LOOPBACK
    }

    public enum BundlePolicy {
        BALANCED,
        MAXBUNDLE,
        MAXCOMPAT
    }

    public enum CandidateNetworkPolicy {
        ALL,
        LOW_COST
    }

    public enum ContinualGatheringPolicy {
        GATHER_ONCE,
        GATHER_CONTINUALLY
    }

    public enum IceTransportsType {
        NONE,
        RELAY,
        NOHOST,
        ALL
    }

    public enum KeyType {
        RSA,
        ECDSA
    }

    public interface Observer {
        void onAddStream(MediaStream mediaStream);

        void onAddTrack(RtpReceiver rtpReceiver, MediaStream[] mediaStreamArr);

        void onDataChannel(DataChannel dataChannel);

        void onIceCandidate(IceCandidate iceCandidate);

        void onIceCandidatesRemoved(IceCandidate[] iceCandidateArr);

        void onIceConnectionChange(IceConnectionState iceConnectionState);

        void onIceConnectionDtlsHandShakeError();

        void onIceConnectionDtlsHandShakeSuccess();

        void onIceConnectionReceivingChange(boolean z);

        void onIceGatheringChange(IceGatheringState iceGatheringState);

        void onRemoveStream(MediaStream mediaStream);

        void onRenegotiationNeeded();

        void onSignalingChange(SignalingState signalingState);

        void onTrack(RtpTransceiver rtpTransceiver);
    }

    public enum RtcpMuxPolicy {
        NEGOTIATE,
        REQUIRE
    }

    public enum SdpSemantics {
        PLAN_B,
        UNIFIED_PLAN
    }

    public enum TcpCandidatePolicy {
        ENABLED,
        DISABLED
    }

    public enum TlsCertPolicy {
        TLS_CERT_POLICY_SECURE,
        TLS_CERT_POLICY_INSECURE_NO_CHECK
    }

    private native boolean nativeAddIceCandidate(String str, int i, String str2);

    private native boolean nativeAddLocalStream(long j);

    private native void nativeAddSSRCGroups(Map<String, Map<Long, Long>> map);

    private native RtpSender nativeAddTrack(long j, List<String> list);

    private native boolean nativeAddTracks(List<RTCTrackInfo> list);

    private native RtpTransceiver nativeAddTransceiverOfType(MediaStreamTrack.MediaType mediaType, RtpTransceiver.RtpTransceiverInit rtpTransceiverInit);

    private native RtpTransceiver nativeAddTransceiverWithTrack(long j, RtpTransceiver.RtpTransceiverInit rtpTransceiverInit);

    private native void nativeApplyAudioStreamRole(int i);

    private native void nativeApplyBitrateSettings(long j, int i, long j2, int i2);

    private native void nativeClose();

    private native void nativeCreateAnswer(SdpObserver sdpObserver, MediaConstraints mediaConstraints);

    private native DataChannel nativeCreateDataChannel(String str, DataChannel.Init init);

    private native void nativeCreateOffer(SdpObserver sdpObserver, MediaConstraints mediaConstraints);

    private static native long nativeCreatePeerConnectionObserver(Observer observer);

    private native RtpSender nativeCreateSender(String str, String str2);

    private static native void nativeFreeOwnedPeerConnection(long j);

    private native SessionDescription nativeGetLocalDescription();

    private native long nativeGetNativePeerConnection();

    private native List<RtpReceiver> nativeGetReceivers();

    private native SessionDescription nativeGetRemoteDescription();

    private native List<RtpSender> nativeGetSenders();

    private native List<RtpTransceiver> nativeGetTransceivers();

    private native IceConnectionState nativeIceConnectionState();

    private native IceGatheringState nativeIceGatheringState();

    private native void nativeNewGetStats(RTCStatsCollectorCallback rTCStatsCollectorCallback);

    private native boolean nativeOldGetStats(StatsObserver statsObserver, long j);

    private native boolean nativeRemoveIceCandidates(IceCandidate[] iceCandidateArr);

    private native void nativeRemoveLocalStream(long j);

    private native void nativeRemoveSSRCGroups(Map<String, Map<Long, Long>> map);

    private native boolean nativeRemoveTrack(long j);

    private native boolean nativeRemoveTracks(List<RTCTrackInfo> list);

    private native void nativeSetAudioPlayout(boolean z);

    private native void nativeSetAudioRecording(boolean z);

    private native boolean nativeSetBitrate(Integer num, Integer num2, Integer num3);

    private native void nativeSetConfigProperty(String str, boolean z);

    private native boolean nativeSetConfiguration(RTCConfiguration rTCConfiguration);

    private native void nativeSetLocalDescription(SdpObserver sdpObserver, SessionDescription sessionDescription);

    private native void nativeSetRemoteDescription(SdpObserver sdpObserver, SessionDescription sessionDescription);

    private native void nativeSetSelectiveOutputVolume(int i, float f);

    private native SignalingState nativeSignalingState();

    private native boolean nativeStartRtcEventLog(int i, int i2);

    private native void nativeStopRtcEventLog();

    public static class SsrcGroup {
        private String semantics;
        private List<Long> ssrcs;

        public boolean hasSemantics(String semantics) {
            String str = this.semantics;
            if (str != null && semantics != null && str.equals(semantics) && !this.ssrcs.isEmpty()) {
                return true;
            }
            return false;
        }

        public String getSemantics() {
            return this.semantics;
        }

        public SsrcGroup(String semantics, List<Long> ssrcs) {
            this.ssrcs = new ArrayList();
            this.semantics = semantics;
            this.ssrcs = ssrcs;
        }

        public List<Long> getSsrcs() {
            return this.ssrcs;
        }
    }

    public static class StreamParams {
        public static final String FEC_FR_SSRC_GROUP_SEMANTICS = "FEC-FR";
        public static final String FEC_SSRC_GROUP_SEMANTICS = "FEC";
        public static final String FID_SSRC_GROUP_SEMANTICS = "FID";
        public static final String SIM_SSRC_GROUP_SEMANTICS = "SIM";
        private String cname;
        private String groupId;
        private String id;
        private List<String> streamIds = new ArrayList();
        private List<Long> ssrcs = new ArrayList();
        private List<SsrcGroup> ssrcGroups = new ArrayList();

        public void setId(String id) {
            this.id = id;
        }

        public String getId() {
            return this.id;
        }

        public Long getFirstSsrc() {
            if (this.ssrcs.isEmpty()) {
                return 0L;
            }
            return this.ssrcs.get(0);
        }

        public boolean hasSsrcs() {
            return !this.ssrcs.isEmpty();
        }

        public boolean hasSsrc(Long ssrc) {
            return this.ssrcs.contains(ssrc);
        }

        public void addSsrc(Long ssrc) {
            this.ssrcs.add(ssrc);
        }

        public boolean hasSsrcGroups() {
            return !this.ssrcGroups.isEmpty();
        }

        public SsrcGroup getSsrcGroup(String semantics) {
            for (SsrcGroup group : this.ssrcGroups) {
                if (group.hasSemantics(semantics)) {
                    return group;
                }
            }
            return null;
        }

        public void addFidSsrc(Long primarySsrc, Long fidSsrc) {
            addSecondarySsrc(FID_SSRC_GROUP_SEMANTICS, primarySsrc, fidSsrc);
        }

        public Long getFidSsrc(Long primarySsrc) {
            return getSecondarySsrc(FID_SSRC_GROUP_SEMANTICS, primarySsrc);
        }

        public void addFecSsrc(Long primarySsrc, Long fecSsrc) {
            addSecondarySsrc(FEC_FR_SSRC_GROUP_SEMANTICS, primarySsrc, fecSsrc);
        }

        public Long getFecSsrc(Long primarySsrc) {
            return getSecondarySsrc(FEC_FR_SSRC_GROUP_SEMANTICS, primarySsrc);
        }

        public List<Long> getPrimarySsrcs() {
            return this.ssrcs;
        }

        public List<String> getStreamIds() {
            return this.streamIds;
        }

        public void setStreamIds(List<String> streamIds) {
            this.streamIds = streamIds;
        }

        public String getFirstStreamId() {
            if (this.streamIds.size() > 0) {
                return this.streamIds.get(0);
            }
            return "";
        }

        public String getGroupId() {
            return this.groupId;
        }

        public void setGroupId(String groupId) {
            this.groupId = groupId;
        }

        public String getCname() {
            return this.cname;
        }

        public void setCname(String cname) {
            this.cname = cname;
        }

        public List<Long> getSsrcs() {
            return this.ssrcs;
        }

        public List<SsrcGroup> getSsrcGroups() {
            return this.ssrcGroups;
        }

        private boolean addSecondarySsrc(String semantics, Long primarySsrc, Long secondarySsrc) {
            if (!hasSsrc(primarySsrc) || primarySsrc.longValue() < 0 || secondarySsrc.longValue() < 0) {
                return false;
            }
            this.ssrcs.add(secondarySsrc);
            List<Long> ssrcList = new ArrayList<>();
            ssrcList.add(primarySsrc);
            ssrcList.add(secondarySsrc);
            SsrcGroup ssrcGroup = new SsrcGroup(semantics, ssrcList);
            this.ssrcGroups.add(ssrcGroup);
            return true;
        }

        private Long getSecondarySsrc(String semantics, Long primarySsrc) {
            for (SsrcGroup group : this.ssrcGroups) {
                if (group.hasSemantics(semantics) && group.getSsrcs().get(0).equals(primarySsrc)) {
                    return group.getSsrcs().get(1);
                }
            }
            return 0L;
        }
    }

    public static class RTCTrackInfo {
        public static final int DIRECTION_INACTIVE = 3;
        public static final int DIRECTION_RECV_ONLY = 2;
        public static final int DIRECTION_SEND_ONLY = 1;
        public static final int DIRECTION_SEND_RECV = 0;
        public static final int MEDIA_TYPE_AUDIO = 0;
        public static final int MEDIA_TYPE_DATA = 2;
        public static final int MEDIA_TYPE_VIDEO = 1;
        private boolean isSelectiveTrack;
        private int mediaType;
        private long nativeTrack;
        private String streamId;
        private int direction = 0;
        private StreamParams streamParams = new StreamParams();

        public int getDirection() {
            return this.direction;
        }

        public void setDirection(int direction) {
            this.direction = direction;
        }

        public int getMediaType() {
            return this.mediaType;
        }

        public void setMediaType(int mediaType) {
            this.mediaType = mediaType;
        }

        public String getStreamId() {
            return this.streamId;
        }

        public void setStreamId(String streamId) {
            this.streamId = streamId;
        }

        public StreamParams getStreamParams() {
            return this.streamParams;
        }

        public long getNativeTrack() {
            return this.nativeTrack;
        }

        public void setTrack(MediaStreamTrack track) {
            if (track != null) {
                this.nativeTrack = track.nativeTrack;
            }
        }

        public boolean isSelectiveTrack() {
            return this.isSelectiveTrack;
        }

        public void setSelectiveTrack(boolean isSelectiveTrack) {
            this.isSelectiveTrack = isSelectiveTrack;
        }
    }

    public enum IceGatheringState {
        NEW,
        GATHERING,
        COMPLETE;

        static IceGatheringState fromNativeIndex(int nativeIndex) {
            return values()[nativeIndex];
        }
    }

    public enum IceConnectionState {
        NEW,
        CHECKING,
        CONNECTED,
        COMPLETED,
        FAILED,
        DISCONNECTED,
        CLOSED;

        static IceConnectionState fromNativeIndex(int nativeIndex) {
            return values()[nativeIndex];
        }
    }

    public enum SignalingState {
        STABLE,
        HAVE_LOCAL_OFFER,
        HAVE_LOCAL_PRANSWER,
        HAVE_REMOTE_OFFER,
        HAVE_REMOTE_PRANSWER,
        CLOSED;

        static SignalingState fromNativeIndex(int nativeIndex) {
            return values()[nativeIndex];
        }
    }

    public static class IceServer {
        public final String hostname;
        public final String password;
        public final List<String> tlsAlpnProtocols;
        public final TlsCertPolicy tlsCertPolicy;
        public final List<String> tlsEllipticCurves;

        @Deprecated
        public final String uri;
        public final List<String> urls;
        public final String username;

        @Deprecated
        public IceServer(String uri) {
            this(uri, "", "");
        }

        @Deprecated
        public IceServer(String uri, String username, String password) {
            this(uri, username, password, TlsCertPolicy.TLS_CERT_POLICY_SECURE);
        }

        @Deprecated
        public IceServer(String uri, String username, String password, TlsCertPolicy tlsCertPolicy) {
            this(uri, username, password, tlsCertPolicy, "");
        }

        @Deprecated
        public IceServer(String uri, String username, String password, TlsCertPolicy tlsCertPolicy, String hostname) {
            this(uri, Collections.singletonList(uri), username, password, tlsCertPolicy, hostname, null, null);
        }

        private IceServer(String uri, List<String> urls, String username, String password, TlsCertPolicy tlsCertPolicy, String hostname, List<String> tlsAlpnProtocols, List<String> tlsEllipticCurves) {
            if (uri == null || urls == null || urls.isEmpty()) {
                throw new IllegalArgumentException("uri == null || urls == null || urls.isEmpty()");
            }
            for (String it : urls) {
                if (it == null) {
                    throw new IllegalArgumentException("urls element is null: " + urls);
                }
            }
            if (username == null) {
                throw new IllegalArgumentException("username == null");
            }
            if (password == null) {
                throw new IllegalArgumentException("password == null");
            }
            if (hostname == null) {
                throw new IllegalArgumentException("hostname == null");
            }
            this.uri = uri;
            this.urls = urls;
            this.username = username;
            this.password = password;
            this.tlsCertPolicy = tlsCertPolicy;
            this.hostname = hostname;
            this.tlsAlpnProtocols = tlsAlpnProtocols;
            this.tlsEllipticCurves = tlsEllipticCurves;
        }

        public String toString() {
            return this.urls + " [" + this.username + LogUtils.COLON + this.password + "] [" + this.tlsCertPolicy + "] [" + this.hostname + "] [" + this.tlsAlpnProtocols + "] [" + this.tlsEllipticCurves + "]";
        }

        public static Builder builder(String uri) {
            return new Builder(Collections.singletonList(uri));
        }

        public static Builder builder(List<String> urls) {
            return new Builder(urls);
        }

        public static class Builder {
            private String hostname;
            private String password;
            private List<String> tlsAlpnProtocols;
            private TlsCertPolicy tlsCertPolicy;
            private List<String> tlsEllipticCurves;

            @Nullable
            private final List<String> urls;
            private String username;

            private Builder(List<String> urls) {
                this.username = "";
                this.password = "";
                this.tlsCertPolicy = TlsCertPolicy.TLS_CERT_POLICY_SECURE;
                this.hostname = "";
                if (urls == null || urls.isEmpty()) {
                    throw new IllegalArgumentException("urls == null || urls.isEmpty(): " + urls);
                }
                this.urls = urls;
            }

            public Builder setUsername(String username) {
                this.username = username;
                return this;
            }

            public Builder setPassword(String password) {
                this.password = password;
                return this;
            }

            public Builder setTlsCertPolicy(TlsCertPolicy tlsCertPolicy) {
                this.tlsCertPolicy = tlsCertPolicy;
                return this;
            }

            public Builder setHostname(String hostname) {
                this.hostname = hostname;
                return this;
            }

            public Builder setTlsAlpnProtocols(List<String> tlsAlpnProtocols) {
                this.tlsAlpnProtocols = tlsAlpnProtocols;
                return this;
            }

            public Builder setTlsEllipticCurves(List<String> tlsEllipticCurves) {
                this.tlsEllipticCurves = tlsEllipticCurves;
                return this;
            }

            public IceServer createIceServer() {
                return new IceServer(this.urls.get(0), this.urls, this.username, this.password, this.tlsCertPolicy, this.hostname, this.tlsAlpnProtocols, this.tlsEllipticCurves);
            }
        }

        @Nullable
        List<String> getUrls() {
            return this.urls;
        }

        @Nullable
        String getUsername() {
            return this.username;
        }

        @Nullable
        String getPassword() {
            return this.password;
        }

        TlsCertPolicy getTlsCertPolicy() {
            return this.tlsCertPolicy;
        }

        @Nullable
        String getHostname() {
            return this.hostname;
        }

        List<String> getTlsAlpnProtocols() {
            return this.tlsAlpnProtocols;
        }

        List<String> getTlsEllipticCurves() {
            return this.tlsEllipticCurves;
        }
    }

    public static class IntervalRange {
        private final int max;
        private final int min;

        public IntervalRange(int min, int max) {
            this.min = min;
            this.max = max;
        }

        public int getMin() {
            return this.min;
        }

        public int getMax() {
            return this.max;
        }
    }

    public static class RTCConfiguration {
        public List<IceServer> iceServers;

        @Nullable
        public TurnCustomizer turnCustomizer;
        public IceTransportsType iceTransportsType = IceTransportsType.ALL;
        public BundlePolicy bundlePolicy = BundlePolicy.BALANCED;
        public RtcpMuxPolicy rtcpMuxPolicy = RtcpMuxPolicy.REQUIRE;
        public TcpCandidatePolicy tcpCandidatePolicy = TcpCandidatePolicy.ENABLED;
        public CandidateNetworkPolicy candidateNetworkPolicy = CandidateNetworkPolicy.ALL;
        public int audioJitterBufferMaxPackets = 150;
        public boolean audioJitterBufferFastAccelerate = false;
        public int iceConnectionReceivingTimeout = -1;
        public int iceBackupCandidatePairPingInterval = -1;
        public KeyType keyType = KeyType.ECDSA;
        public ContinualGatheringPolicy continualGatheringPolicy = ContinualGatheringPolicy.GATHER_ONCE;
        public int iceCandidatePoolSize = 0;
        public boolean pruneTurnPorts = false;
        public boolean presumeWritableWhenFullyRelayed = false;

        @Nullable
        public Integer iceCheckIntervalStrongConnectivityMs = null;

        @Nullable
        public Integer iceCheckIntervalWeakConnectivityMs = null;

        @Nullable
        public Integer iceCheckMinInterval = null;

        @Nullable
        public Integer iceUnwritableTimeMs = null;

        @Nullable
        public Integer iceUnwritableMinChecks = null;

        @Nullable
        public Integer stunCandidateKeepaliveIntervalMs = null;
        public boolean disableIPv6OnWifi = false;
        public int maxIPv6Networks = 5;

        @Nullable
        public IntervalRange iceRegatherIntervalRange = null;
        public boolean disableIpv6 = true;
        public boolean enableDscp = false;
        public boolean enableCpuOveruseDetection = true;
        public boolean enableRtpDataChannel = false;
        public boolean suspendBelowMinBitrate = false;

        @Nullable
        public Integer screencastMinBitrate = null;

        @Nullable
        public Boolean combinedAudioVideoBwe = null;

        @Nullable
        public Boolean enableDtlsSrtp = null;
        public AdapterType networkPreference = AdapterType.UNKNOWN;
        public SdpSemantics sdpSemantics = SdpSemantics.PLAN_B;
        public boolean activeResetSrtpParams = false;

        public RTCConfiguration(List<IceServer> iceServers) {
            this.iceServers = iceServers;
        }

        IceTransportsType getIceTransportsType() {
            return this.iceTransportsType;
        }

        List<IceServer> getIceServers() {
            return this.iceServers;
        }

        BundlePolicy getBundlePolicy() {
            return this.bundlePolicy;
        }

        RtcpMuxPolicy getRtcpMuxPolicy() {
            return this.rtcpMuxPolicy;
        }

        TcpCandidatePolicy getTcpCandidatePolicy() {
            return this.tcpCandidatePolicy;
        }

        CandidateNetworkPolicy getCandidateNetworkPolicy() {
            return this.candidateNetworkPolicy;
        }

        int getAudioJitterBufferMaxPackets() {
            return this.audioJitterBufferMaxPackets;
        }

        boolean getAudioJitterBufferFastAccelerate() {
            return this.audioJitterBufferFastAccelerate;
        }

        int getIceConnectionReceivingTimeout() {
            return this.iceConnectionReceivingTimeout;
        }

        int getIceBackupCandidatePairPingInterval() {
            return this.iceBackupCandidatePairPingInterval;
        }

        KeyType getKeyType() {
            return this.keyType;
        }

        ContinualGatheringPolicy getContinualGatheringPolicy() {
            return this.continualGatheringPolicy;
        }

        int getIceCandidatePoolSize() {
            return this.iceCandidatePoolSize;
        }

        boolean getPruneTurnPorts() {
            return this.pruneTurnPorts;
        }

        boolean getPresumeWritableWhenFullyRelayed() {
            return this.presumeWritableWhenFullyRelayed;
        }

        @Nullable
        Integer getIceCheckIntervalStrongConnectivity() {
            return this.iceCheckIntervalStrongConnectivityMs;
        }

        @Nullable
        Integer getIceCheckIntervalWeakConnectivity() {
            return this.iceCheckIntervalWeakConnectivityMs;
        }

        @Nullable
        Integer getIceCheckMinInterval() {
            return this.iceCheckMinInterval;
        }

        @Nullable
        Integer getIceUnwritableTimeout() {
            return this.iceUnwritableTimeMs;
        }

        @Nullable
        Integer getIceUnwritableMinChecks() {
            return this.iceUnwritableMinChecks;
        }

        @Nullable
        Integer getStunCandidateKeepaliveInterval() {
            return this.stunCandidateKeepaliveIntervalMs;
        }

        boolean getDisableIPv6OnWifi() {
            return this.disableIPv6OnWifi;
        }

        int getMaxIPv6Networks() {
            return this.maxIPv6Networks;
        }

        @Nullable
        IntervalRange getIceRegatherIntervalRange() {
            return this.iceRegatherIntervalRange;
        }

        @Nullable
        TurnCustomizer getTurnCustomizer() {
            return this.turnCustomizer;
        }

        boolean getDisableIpv6() {
            return this.disableIpv6;
        }

        boolean getEnableDscp() {
            return this.enableDscp;
        }

        boolean getEnableCpuOveruseDetection() {
            return this.enableCpuOveruseDetection;
        }

        boolean getEnableRtpDataChannel() {
            return this.enableRtpDataChannel;
        }

        boolean getSuspendBelowMinBitrate() {
            return this.suspendBelowMinBitrate;
        }

        @Nullable
        Integer getScreencastMinBitrate() {
            return this.screencastMinBitrate;
        }

        @Nullable
        Boolean getCombinedAudioVideoBwe() {
            return this.combinedAudioVideoBwe;
        }

        @Nullable
        Boolean getEnableDtlsSrtp() {
            return this.enableDtlsSrtp;
        }

        AdapterType getNetworkPreference() {
            return this.networkPreference;
        }

        SdpSemantics getSdpSemantics() {
            return this.sdpSemantics;
        }

        boolean getActiveResetSrtpParams() {
            return this.activeResetSrtpParams;
        }
    }

    public PeerConnection(NativePeerConnectionFactory factory) {
        this(factory.createNativePeerConnection());
    }

    PeerConnection(long nativePeerConnection) {
        this.localStreams = new ArrayList();
        this.senders = new ArrayList();
        this.receivers = new ArrayList();
        this.transceivers = new ArrayList();
        this.nativePeerConnection = nativePeerConnection;
    }

    public void setNativeOwtFactory(long nativeOwtFactory) {
        this.nativeOwtFactory = nativeOwtFactory;
    }

    public SessionDescription getLocalDescription() {
        return nativeGetLocalDescription();
    }

    public SessionDescription getRemoteDescription() {
        return nativeGetRemoteDescription();
    }

    public DataChannel createDataChannel(String label, DataChannel.Init init) {
        return nativeCreateDataChannel(label, init);
    }

    public void createOffer(SdpObserver observer, MediaConstraints constraints) {
        nativeCreateOffer(observer, constraints);
    }

    public void applyBitrateSettings(RtpSender sender, int backward_compatible_bitrate) {
        if (sender == null || sender.disposed()) {
            return;
        }
        nativeApplyBitrateSettings(sender.nativeRtpSender, backward_compatible_bitrate, this.nativeOwtFactory, 0);
    }

    public void applyBitrateSettings(RtpSender sender, int backward_compatible_bitrate, int failover_count) {
        if (sender == null || sender.disposed()) {
            return;
        }
        nativeApplyBitrateSettings(sender.nativeRtpSender, backward_compatible_bitrate, this.nativeOwtFactory, failover_count);
    }

    public void createAnswer(SdpObserver observer, MediaConstraints constraints) {
        nativeCreateAnswer(observer, constraints);
    }

    public void setLocalDescription(SdpObserver observer, SessionDescription sdp) {
        nativeSetLocalDescription(observer, sdp);
    }

    public void setRemoteDescription(SdpObserver observer, SessionDescription sdp) {
        nativeSetRemoteDescription(observer, sdp);
    }

    public void setAudioPlayout(boolean playout) {
        nativeSetAudioPlayout(playout);
    }

    public void setAudioRecording(boolean recording) {
        nativeSetAudioRecording(recording);
    }

    public boolean setConfiguration(RTCConfiguration config) {
        return nativeSetConfiguration(config);
    }

    public boolean addIceCandidate(IceCandidate candidate) {
        return nativeAddIceCandidate(candidate.sdpMid, candidate.sdpMLineIndex, candidate.sdp);
    }

    public boolean removeIceCandidates(IceCandidate[] candidates) {
        return nativeRemoveIceCandidates(candidates);
    }

    public boolean addStream(MediaStream stream) {
        boolean ret = nativeAddLocalStream(stream.nativeStream);
        if (!ret) {
            return false;
        }
        this.localStreams.add(stream);
        return true;
    }

    public void removeStream(MediaStream stream) {
        nativeRemoveLocalStream(stream.nativeStream);
        this.localStreams.remove(stream);
    }

    public RtpSender createSender(String kind, String stream_id) {
        RtpSender newSender = nativeCreateSender(kind, stream_id);
        if (newSender != null) {
            this.senders.add(newSender);
        }
        return newSender;
    }

    public List<RtpSender> getSenders() {
        for (RtpSender sender : this.senders) {
            sender.dispose();
        }
        List<RtpSender> listNativeGetSenders = nativeGetSenders();
        this.senders = listNativeGetSenders;
        return Collections.unmodifiableList(listNativeGetSenders);
    }

    public List<RtpReceiver> getReceivers() {
        for (RtpReceiver receiver : this.receivers) {
            receiver.dispose();
        }
        List<RtpReceiver> listNativeGetReceivers = nativeGetReceivers();
        this.receivers = listNativeGetReceivers;
        return Collections.unmodifiableList(listNativeGetReceivers);
    }

    public List<RtpTransceiver> getTransceivers() {
        for (RtpTransceiver transceiver : this.transceivers) {
            transceiver.dispose();
        }
        List<RtpTransceiver> listNativeGetTransceivers = nativeGetTransceivers();
        this.transceivers = listNativeGetTransceivers;
        return Collections.unmodifiableList(listNativeGetTransceivers);
    }

    public RtpSender addTrack(MediaStreamTrack track) {
        return addTrack(track, Collections.emptyList());
    }

    public RtpSender addTrack(MediaStreamTrack track, List<String> streamIds) {
        if (track == null || streamIds == null) {
            throw new NullPointerException("No MediaStreamTrack specified in addTrack.");
        }
        RtpSender newSender = nativeAddTrack(track.nativeTrack, streamIds);
        if (newSender == null) {
            throw new IllegalStateException("C++ addTrack failed.");
        }
        this.senders.add(newSender);
        return newSender;
    }

    public void addTracks(List<RTCTrackInfo> trackInfos) {
        nativeAddTracks(trackInfos);
    }

    public void removeTracks(List<RTCTrackInfo> trackInfos) {
        nativeRemoveTracks(trackInfos);
    }

    public boolean removeTrack(RtpSender sender) {
        if (sender == null) {
            throw new NullPointerException("No RtpSender specified for removeTrack.");
        }
        return nativeRemoveTrack(sender.nativeRtpSender);
    }

    public RtpTransceiver addTransceiver(MediaStreamTrack track) {
        return addTransceiver(track, new RtpTransceiver.RtpTransceiverInit());
    }

    public RtpTransceiver addTransceiver(MediaStreamTrack track, @Nullable RtpTransceiver.RtpTransceiverInit init) {
        if (track == null) {
            throw new NullPointerException("No MediaStreamTrack specified for addTransceiver.");
        }
        if (init == null) {
            init = new RtpTransceiver.RtpTransceiverInit();
        }
        RtpTransceiver newTransceiver = nativeAddTransceiverWithTrack(track.nativeTrack, init);
        if (newTransceiver == null) {
            throw new IllegalStateException("C++ addTransceiver failed.");
        }
        this.transceivers.add(newTransceiver);
        return newTransceiver;
    }

    public RtpTransceiver addTransceiver(MediaStreamTrack.MediaType mediaType) {
        return addTransceiver(mediaType, new RtpTransceiver.RtpTransceiverInit());
    }

    public RtpTransceiver addTransceiver(MediaStreamTrack.MediaType mediaType, @Nullable RtpTransceiver.RtpTransceiverInit init) {
        if (mediaType == null) {
            throw new NullPointerException("No MediaType specified for addTransceiver.");
        }
        if (init == null) {
            init = new RtpTransceiver.RtpTransceiverInit();
        }
        RtpTransceiver newTransceiver = nativeAddTransceiverOfType(mediaType, init);
        if (newTransceiver == null) {
            throw new IllegalStateException("C++ addTransceiver failed.");
        }
        this.transceivers.add(newTransceiver);
        return newTransceiver;
    }

    @Deprecated
    public boolean getStats(StatsObserver observer, @Nullable MediaStreamTrack track) {
        return nativeOldGetStats(observer, track == null ? 0L : track.nativeTrack);
    }

    public void getStats(RTCStatsCollectorCallback callback) {
        nativeNewGetStats(callback);
    }

    public boolean setBitrate(Integer min, Integer current, Integer max) {
        return nativeSetBitrate(min, current, max);
    }

    public boolean startRtcEventLog(int file_descriptor, int max_size_bytes) {
        return nativeStartRtcEventLog(file_descriptor, max_size_bytes);
    }

    public void stopRtcEventLog() {
        nativeStopRtcEventLog();
    }

    public void setConfigProperty(String key, boolean value) {
        nativeSetConfigProperty(key, value);
    }

    public SignalingState signalingState() {
        return nativeSignalingState();
    }

    public IceConnectionState iceConnectionState() {
        return nativeIceConnectionState();
    }

    public IceGatheringState iceGatheringState() {
        return nativeIceGatheringState();
    }

    public void close() {
        nativeClose();
    }

    public void applyAudioStreamRole(int audioStreamRole) {
        nativeApplyAudioStreamRole(audioStreamRole);
    }

    public void addSSRCGroups(Map<String, Map<Long, Long>> ssrcGroups) {
        nativeAddSSRCGroups(ssrcGroups);
    }

    public void removeSSRCGroups(Map<String, Map<Long, Long>> ssrcGroups) {
        nativeRemoveSSRCGroups(ssrcGroups);
    }

    public void setSelectiveOutputVolume(int ssrc, float volume) {
        nativeSetSelectiveOutputVolume(ssrc, volume);
    }

    public void setCustomerInfo(String key, String value) {
        String pc_handle = Long.toHexString(getNativePeerConnection());
        Logging.d(TAG, "peerconnection[0x" + pc_handle + "]: customerInfo " + key + LogUtils.COLON + value);
    }

    public void dispose() {
        close();
        for (MediaStream stream : this.localStreams) {
            nativeRemoveLocalStream(stream.nativeStream);
            stream.dispose();
        }
        this.localStreams.clear();
        for (RtpSender sender : this.senders) {
            sender.dispose();
        }
        this.senders.clear();
        for (RtpReceiver receiver : this.receivers) {
            receiver.dispose();
        }
        for (RtpTransceiver transceiver : this.transceivers) {
            transceiver.dispose();
        }
        this.transceivers.clear();
        this.receivers.clear();
        nativeFreeOwnedPeerConnection(this.nativePeerConnection);
    }

    public long getNativePeerConnection() {
        return nativeGetNativePeerConnection();
    }

    long getNativeOwnedPeerConnection() {
        return this.nativePeerConnection;
    }

    public static long createNativePeerConnectionObserver(Observer observer) {
        return nativeCreatePeerConnectionObserver(observer);
    }
}
