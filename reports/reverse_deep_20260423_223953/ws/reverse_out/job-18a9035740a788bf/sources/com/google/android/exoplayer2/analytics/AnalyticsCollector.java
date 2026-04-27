package com.google.android.exoplayer2.analytics;

import android.graphics.SurfaceTexture;
import android.view.Surface;
import com.google.android.exoplayer2.ExoPlaybackException;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.PlaybackParameters;
import com.google.android.exoplayer2.Player;
import com.google.android.exoplayer2.Timeline;
import com.google.android.exoplayer2.analytics.AnalyticsListener;
import com.google.android.exoplayer2.audio.AudioAttributes;
import com.google.android.exoplayer2.audio.AudioListener;
import com.google.android.exoplayer2.audio.AudioRendererEventListener;
import com.google.android.exoplayer2.decoder.DecoderCounters;
import com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.MetadataOutput;
import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.source.MediaSourceEventListener;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.TrackSelectionArray;
import com.google.android.exoplayer2.upstream.BandwidthMeter;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Clock;
import com.google.android.exoplayer2.video.VideoListener;
import com.google.android.exoplayer2.video.VideoRendererEventListener;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import org.checkerframework.checker.nullness.qual.RequiresNonNull;

/* JADX INFO: loaded from: classes2.dex */
public class AnalyticsCollector implements Player.EventListener, MetadataOutput, AudioRendererEventListener, VideoRendererEventListener, MediaSourceEventListener, BandwidthMeter.EventListener, DefaultDrmSessionEventListener, VideoListener, AudioListener {
    private final Clock clock;
    private final CopyOnWriteArraySet<AnalyticsListener> listeners;
    private final MediaPeriodQueueTracker mediaPeriodQueueTracker;
    private Player player;
    private final Timeline.Window window;

    public static class Factory {
        public AnalyticsCollector createAnalyticsCollector(Player player, Clock clock) {
            return new AnalyticsCollector(player, clock);
        }
    }

    protected AnalyticsCollector(Player player, Clock clock) {
        if (player != null) {
            this.player = player;
        }
        this.clock = (Clock) Assertions.checkNotNull(clock);
        this.listeners = new CopyOnWriteArraySet<>();
        this.mediaPeriodQueueTracker = new MediaPeriodQueueTracker();
        this.window = new Timeline.Window();
    }

    public void addListener(AnalyticsListener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(AnalyticsListener listener) {
        this.listeners.remove(listener);
    }

    public void setPlayer(Player player) {
        Assertions.checkState(this.player == null);
        this.player = (Player) Assertions.checkNotNull(player);
    }

    public final void notifySeekStarted() {
        if (!this.mediaPeriodQueueTracker.isSeeking()) {
            AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
            this.mediaPeriodQueueTracker.onSeekStarted();
            for (AnalyticsListener listener : this.listeners) {
                listener.onSeekStarted(eventTime);
            }
        }
    }

    public final void resetForNewMediaSource() {
        List<MediaPeriodInfo> mediaPeriodInfos = new ArrayList<>(this.mediaPeriodQueueTracker.mediaPeriodInfoQueue);
        for (MediaPeriodInfo mediaPeriodInfo : mediaPeriodInfos) {
            onMediaPeriodReleased(mediaPeriodInfo.windowIndex, mediaPeriodInfo.mediaPeriodId);
        }
    }

    @Override // com.google.android.exoplayer2.metadata.MetadataOutput
    public final void onMetadata(Metadata metadata) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onMetadata(eventTime, metadata);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioRendererEventListener
    public final void onAudioEnabled(DecoderCounters counters) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderEnabled(eventTime, 1, counters);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioRendererEventListener
    public final void onAudioDecoderInitialized(String decoderName, long initializedTimestampMs, long initializationDurationMs) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderInitialized(eventTime, 1, decoderName, initializationDurationMs);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioRendererEventListener
    public final void onAudioInputFormatChanged(Format format) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderInputFormatChanged(eventTime, 1, format);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioRendererEventListener
    public final void onAudioSinkUnderrun(int bufferSize, long bufferSizeMs, long elapsedSinceLastFeedMs) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onAudioUnderrun(eventTime, bufferSize, bufferSizeMs, elapsedSinceLastFeedMs);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioRendererEventListener
    public final void onAudioDisabled(DecoderCounters counters) {
        AnalyticsListener.EventTime eventTime = generateLastReportedPlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderDisabled(eventTime, 1, counters);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioRendererEventListener
    public final void onAudioSessionId(int audioSessionId) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onAudioSessionId(eventTime, audioSessionId);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioListener
    public void onAudioAttributesChanged(AudioAttributes audioAttributes) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onAudioAttributesChanged(eventTime, audioAttributes);
        }
    }

    @Override // com.google.android.exoplayer2.audio.AudioListener
    public void onVolumeChanged(float audioVolume) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onVolumeChanged(eventTime, audioVolume);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onVideoEnabled(DecoderCounters counters) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderEnabled(eventTime, 2, counters);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onVideoDecoderInitialized(String decoderName, long initializedTimestampMs, long initializationDurationMs) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderInitialized(eventTime, 2, decoderName, initializationDurationMs);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onVideoInputFormatChanged(Format format) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderInputFormatChanged(eventTime, 2, format);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onDroppedFrames(int count, long elapsedMs) {
        AnalyticsListener.EventTime eventTime = generateLastReportedPlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDroppedVideoFrames(eventTime, count, elapsedMs);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onVideoDisabled(DecoderCounters counters) {
        AnalyticsListener.EventTime eventTime = generateLastReportedPlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDecoderDisabled(eventTime, 2, counters);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onRenderedFirstFrame(Surface surface) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onRenderedFirstFrame(eventTime, surface);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
        return false;
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public final void onRenderedFirstFrame() {
    }

    @Override // com.google.android.exoplayer2.video.VideoRendererEventListener
    public final void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onVideoSizeChanged(eventTime, width, height, unappliedRotationDegrees, pixelWidthHeightRatio);
        }
    }

    @Override // com.google.android.exoplayer2.video.VideoListener
    public void onSurfaceSizeChanged(int width, int height) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onSurfaceSizeChanged(eventTime, width, height);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onMediaPeriodCreated(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId) {
        this.mediaPeriodQueueTracker.onMediaPeriodCreated(windowIndex, mediaPeriodId);
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onMediaPeriodCreated(eventTime);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onMediaPeriodReleased(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        if (this.mediaPeriodQueueTracker.onMediaPeriodReleased(mediaPeriodId)) {
            for (AnalyticsListener listener : this.listeners) {
                listener.onMediaPeriodReleased(eventTime);
            }
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onLoadStarted(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId, MediaSourceEventListener.LoadEventInfo loadEventInfo, MediaSourceEventListener.MediaLoadData mediaLoadData) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onLoadStarted(eventTime, loadEventInfo, mediaLoadData);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onLoadCompleted(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId, MediaSourceEventListener.LoadEventInfo loadEventInfo, MediaSourceEventListener.MediaLoadData mediaLoadData) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onLoadCompleted(eventTime, loadEventInfo, mediaLoadData);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onLoadCanceled(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId, MediaSourceEventListener.LoadEventInfo loadEventInfo, MediaSourceEventListener.MediaLoadData mediaLoadData) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onLoadCanceled(eventTime, loadEventInfo, mediaLoadData);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onLoadError(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId, MediaSourceEventListener.LoadEventInfo loadEventInfo, MediaSourceEventListener.MediaLoadData mediaLoadData, IOException error, boolean wasCanceled) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onLoadError(eventTime, loadEventInfo, mediaLoadData, error, wasCanceled);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onReadingStarted(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId) {
        this.mediaPeriodQueueTracker.onReadingStarted(mediaPeriodId);
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onReadingStarted(eventTime);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onUpstreamDiscarded(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId, MediaSourceEventListener.MediaLoadData mediaLoadData) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onUpstreamDiscarded(eventTime, mediaLoadData);
        }
    }

    @Override // com.google.android.exoplayer2.source.MediaSourceEventListener
    public final void onDownstreamFormatChanged(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId, MediaSourceEventListener.MediaLoadData mediaLoadData) {
        AnalyticsListener.EventTime eventTime = generateMediaPeriodEventTime(windowIndex, mediaPeriodId);
        for (AnalyticsListener listener : this.listeners) {
            listener.onDownstreamFormatChanged(eventTime, mediaLoadData);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onTimelineChanged(Timeline timeline, Object manifest, int reason) {
        this.mediaPeriodQueueTracker.onTimelineChanged(timeline);
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onTimelineChanged(eventTime, reason);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onTracksChanged(TrackGroupArray trackGroups, TrackSelectionArray trackSelections) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onTracksChanged(eventTime, trackGroups, trackSelections);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onLoadingChanged(boolean isLoading) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onLoadingChanged(eventTime, isLoading);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onPlayerStateChanged(boolean playWhenReady, int playbackState) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onPlayerStateChanged(eventTime, playWhenReady, playbackState);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onRepeatModeChanged(int repeatMode) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onRepeatModeChanged(eventTime, repeatMode);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onShuffleModeEnabledChanged(boolean shuffleModeEnabled) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onShuffleModeChanged(eventTime, shuffleModeEnabled);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onPlayerError(ExoPlaybackException error) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onPlayerError(eventTime, error);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onPositionDiscontinuity(int reason) {
        this.mediaPeriodQueueTracker.onPositionDiscontinuity(reason);
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onPositionDiscontinuity(eventTime, reason);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onPlaybackParametersChanged(PlaybackParameters playbackParameters) {
        AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onPlaybackParametersChanged(eventTime, playbackParameters);
        }
    }

    @Override // com.google.android.exoplayer2.Player.EventListener
    public final void onSeekProcessed() {
        if (this.mediaPeriodQueueTracker.isSeeking()) {
            this.mediaPeriodQueueTracker.onSeekProcessed();
            AnalyticsListener.EventTime eventTime = generatePlayingMediaPeriodEventTime();
            for (AnalyticsListener listener : this.listeners) {
                listener.onSeekProcessed(eventTime);
            }
        }
    }

    @Override // com.google.android.exoplayer2.upstream.BandwidthMeter.EventListener
    public final void onBandwidthSample(int elapsedMs, long bytes, long bitrate) {
        AnalyticsListener.EventTime eventTime = generateLoadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onBandwidthEstimate(eventTime, elapsedMs, bytes, bitrate);
        }
    }

    @Override // com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener
    public final void onDrmSessionAcquired() {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDrmSessionAcquired(eventTime);
        }
    }

    @Override // com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener
    public final void onDrmKeysLoaded() {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDrmKeysLoaded(eventTime);
        }
    }

    @Override // com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener
    public final void onDrmSessionManagerError(Exception error) {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDrmSessionManagerError(eventTime, error);
        }
    }

    @Override // com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener
    public final void onDrmKeysRestored() {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDrmKeysRestored(eventTime);
        }
    }

    @Override // com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener
    public final void onDrmKeysRemoved() {
        AnalyticsListener.EventTime eventTime = generateReadingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDrmKeysRemoved(eventTime);
        }
    }

    @Override // com.google.android.exoplayer2.drm.DefaultDrmSessionEventListener
    public final void onDrmSessionReleased() {
        AnalyticsListener.EventTime eventTime = generateLastReportedPlayingMediaPeriodEventTime();
        for (AnalyticsListener listener : this.listeners) {
            listener.onDrmSessionReleased(eventTime);
        }
    }

    protected Set<AnalyticsListener> getListeners() {
        return Collections.unmodifiableSet(this.listeners);
    }

    @RequiresNonNull({"player"})
    protected AnalyticsListener.EventTime generateEventTime(Timeline timeline, int windowIndex, MediaSource.MediaPeriodId mediaPeriodId) {
        MediaSource.MediaPeriodId mediaPeriodId2;
        long eventPositionMs;
        if (!timeline.isEmpty()) {
            mediaPeriodId2 = mediaPeriodId;
        } else {
            mediaPeriodId2 = null;
        }
        long realtimeMs = this.clock.elapsedRealtime();
        boolean isInCurrentWindow = timeline == this.player.getCurrentTimeline() && windowIndex == this.player.getCurrentWindowIndex();
        long defaultPositionMs = 0;
        if (mediaPeriodId2 != null && mediaPeriodId2.isAd()) {
            boolean isCurrentAd = isInCurrentWindow && this.player.getCurrentAdGroupIndex() == mediaPeriodId2.adGroupIndex && this.player.getCurrentAdIndexInAdGroup() == mediaPeriodId2.adIndexInAdGroup;
            if (isCurrentAd) {
                defaultPositionMs = this.player.getCurrentPosition();
            }
            long eventPositionMs2 = defaultPositionMs;
            eventPositionMs = eventPositionMs2;
        } else if (isInCurrentWindow) {
            eventPositionMs = this.player.getContentPosition();
        } else {
            if (!timeline.isEmpty()) {
                defaultPositionMs = timeline.getWindow(windowIndex, this.window).getDefaultPositionMs();
            }
            eventPositionMs = defaultPositionMs;
        }
        return new AnalyticsListener.EventTime(realtimeMs, timeline, windowIndex, mediaPeriodId2, eventPositionMs, this.player.getCurrentPosition(), this.player.getTotalBufferedDuration());
    }

    private AnalyticsListener.EventTime generateEventTime(MediaPeriodInfo mediaPeriodInfo) {
        int windowIndex;
        Assertions.checkNotNull(this.player);
        if (mediaPeriodInfo == null && (mediaPeriodInfo = this.mediaPeriodQueueTracker.tryResolveWindowIndex((windowIndex = this.player.getCurrentWindowIndex()))) == null) {
            Timeline timeline = this.player.getCurrentTimeline();
            boolean windowIsInTimeline = windowIndex < timeline.getWindowCount();
            return generateEventTime(windowIsInTimeline ? timeline : Timeline.EMPTY, windowIndex, null);
        }
        return generateEventTime(mediaPeriodInfo.timeline, mediaPeriodInfo.windowIndex, mediaPeriodInfo.mediaPeriodId);
    }

    private AnalyticsListener.EventTime generateLastReportedPlayingMediaPeriodEventTime() {
        return generateEventTime(this.mediaPeriodQueueTracker.getLastReportedPlayingMediaPeriod());
    }

    private AnalyticsListener.EventTime generatePlayingMediaPeriodEventTime() {
        return generateEventTime(this.mediaPeriodQueueTracker.getPlayingMediaPeriod());
    }

    private AnalyticsListener.EventTime generateReadingMediaPeriodEventTime() {
        return generateEventTime(this.mediaPeriodQueueTracker.getReadingMediaPeriod());
    }

    private AnalyticsListener.EventTime generateLoadingMediaPeriodEventTime() {
        return generateEventTime(this.mediaPeriodQueueTracker.getLoadingMediaPeriod());
    }

    private AnalyticsListener.EventTime generateMediaPeriodEventTime(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId) {
        Assertions.checkNotNull(this.player);
        if (mediaPeriodId != null) {
            MediaPeriodInfo mediaPeriodInfo = this.mediaPeriodQueueTracker.getMediaPeriodInfo(mediaPeriodId);
            if (mediaPeriodInfo != null) {
                return generateEventTime(mediaPeriodInfo);
            }
            return generateEventTime(Timeline.EMPTY, windowIndex, mediaPeriodId);
        }
        Timeline timeline = this.player.getCurrentTimeline();
        boolean windowIsInTimeline = windowIndex < timeline.getWindowCount();
        return generateEventTime(windowIsInTimeline ? timeline : Timeline.EMPTY, windowIndex, null);
    }

    private static final class MediaPeriodQueueTracker {
        private boolean isSeeking;
        private MediaPeriodInfo lastReportedPlayingMediaPeriod;
        private MediaPeriodInfo readingMediaPeriod;
        private final ArrayList<MediaPeriodInfo> mediaPeriodInfoQueue = new ArrayList<>();
        private final HashMap<MediaSource.MediaPeriodId, MediaPeriodInfo> mediaPeriodIdToInfo = new HashMap<>();
        private final Timeline.Period period = new Timeline.Period();
        private Timeline timeline = Timeline.EMPTY;

        public MediaPeriodInfo getPlayingMediaPeriod() {
            if (this.mediaPeriodInfoQueue.isEmpty() || this.timeline.isEmpty() || this.isSeeking) {
                return null;
            }
            return this.mediaPeriodInfoQueue.get(0);
        }

        public MediaPeriodInfo getLastReportedPlayingMediaPeriod() {
            return this.lastReportedPlayingMediaPeriod;
        }

        public MediaPeriodInfo getReadingMediaPeriod() {
            return this.readingMediaPeriod;
        }

        public MediaPeriodInfo getLoadingMediaPeriod() {
            if (this.mediaPeriodInfoQueue.isEmpty()) {
                return null;
            }
            return this.mediaPeriodInfoQueue.get(r0.size() - 1);
        }

        public MediaPeriodInfo getMediaPeriodInfo(MediaSource.MediaPeriodId mediaPeriodId) {
            return this.mediaPeriodIdToInfo.get(mediaPeriodId);
        }

        public boolean isSeeking() {
            return this.isSeeking;
        }

        public MediaPeriodInfo tryResolveWindowIndex(int windowIndex) {
            MediaPeriodInfo match = null;
            for (int i = 0; i < this.mediaPeriodInfoQueue.size(); i++) {
                MediaPeriodInfo info = this.mediaPeriodInfoQueue.get(i);
                int periodIndex = this.timeline.getIndexOfPeriod(info.mediaPeriodId.periodUid);
                if (periodIndex != -1 && this.timeline.getPeriod(periodIndex, this.period).windowIndex == windowIndex) {
                    if (match != null) {
                        return null;
                    }
                    match = info;
                }
            }
            return match;
        }

        public void onPositionDiscontinuity(int reason) {
            updateLastReportedPlayingMediaPeriod();
        }

        public void onTimelineChanged(Timeline timeline) {
            for (int i = 0; i < this.mediaPeriodInfoQueue.size(); i++) {
                MediaPeriodInfo newMediaPeriodInfo = updateMediaPeriodInfoToNewTimeline(this.mediaPeriodInfoQueue.get(i), timeline);
                this.mediaPeriodInfoQueue.set(i, newMediaPeriodInfo);
                this.mediaPeriodIdToInfo.put(newMediaPeriodInfo.mediaPeriodId, newMediaPeriodInfo);
            }
            MediaPeriodInfo mediaPeriodInfo = this.readingMediaPeriod;
            if (mediaPeriodInfo != null) {
                this.readingMediaPeriod = updateMediaPeriodInfoToNewTimeline(mediaPeriodInfo, timeline);
            }
            this.timeline = timeline;
            updateLastReportedPlayingMediaPeriod();
        }

        public void onSeekStarted() {
            this.isSeeking = true;
        }

        public void onSeekProcessed() {
            this.isSeeking = false;
            updateLastReportedPlayingMediaPeriod();
        }

        public void onMediaPeriodCreated(int windowIndex, MediaSource.MediaPeriodId mediaPeriodId) {
            boolean isInTimeline = this.timeline.getIndexOfPeriod(mediaPeriodId.periodUid) != -1;
            MediaPeriodInfo mediaPeriodInfo = new MediaPeriodInfo(mediaPeriodId, isInTimeline ? this.timeline : Timeline.EMPTY, windowIndex);
            this.mediaPeriodInfoQueue.add(mediaPeriodInfo);
            this.mediaPeriodIdToInfo.put(mediaPeriodId, mediaPeriodInfo);
            if (this.mediaPeriodInfoQueue.size() == 1 && !this.timeline.isEmpty()) {
                updateLastReportedPlayingMediaPeriod();
            }
        }

        public boolean onMediaPeriodReleased(MediaSource.MediaPeriodId mediaPeriodId) {
            MediaPeriodInfo mediaPeriodInfo = this.mediaPeriodIdToInfo.remove(mediaPeriodId);
            if (mediaPeriodInfo == null) {
                return false;
            }
            this.mediaPeriodInfoQueue.remove(mediaPeriodInfo);
            MediaPeriodInfo mediaPeriodInfo2 = this.readingMediaPeriod;
            if (mediaPeriodInfo2 != null && mediaPeriodId.equals(mediaPeriodInfo2.mediaPeriodId)) {
                this.readingMediaPeriod = this.mediaPeriodInfoQueue.isEmpty() ? null : this.mediaPeriodInfoQueue.get(0);
                return true;
            }
            return true;
        }

        public void onReadingStarted(MediaSource.MediaPeriodId mediaPeriodId) {
            this.readingMediaPeriod = this.mediaPeriodIdToInfo.get(mediaPeriodId);
        }

        private void updateLastReportedPlayingMediaPeriod() {
            if (!this.mediaPeriodInfoQueue.isEmpty()) {
                this.lastReportedPlayingMediaPeriod = this.mediaPeriodInfoQueue.get(0);
            }
        }

        private MediaPeriodInfo updateMediaPeriodInfoToNewTimeline(MediaPeriodInfo info, Timeline newTimeline) {
            int newPeriodIndex = newTimeline.getIndexOfPeriod(info.mediaPeriodId.periodUid);
            if (newPeriodIndex == -1) {
                return info;
            }
            int newWindowIndex = newTimeline.getPeriod(newPeriodIndex, this.period).windowIndex;
            return new MediaPeriodInfo(info.mediaPeriodId, newTimeline, newWindowIndex);
        }
    }

    private static final class MediaPeriodInfo {
        public final MediaSource.MediaPeriodId mediaPeriodId;
        public final Timeline timeline;
        public final int windowIndex;

        public MediaPeriodInfo(MediaSource.MediaPeriodId mediaPeriodId, Timeline timeline, int windowIndex) {
            this.mediaPeriodId = mediaPeriodId;
            this.timeline = timeline;
            this.windowIndex = windowIndex;
        }
    }
}
