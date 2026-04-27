package com.google.android.exoplayer2;

import android.util.Pair;
import com.google.android.exoplayer2.Timeline;
import com.google.android.exoplayer2.source.MediaPeriod;
import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.trackselection.TrackSelector;
import com.google.android.exoplayer2.upstream.Allocator;
import com.google.android.exoplayer2.util.Assertions;

/* JADX INFO: loaded from: classes2.dex */
final class MediaPeriodQueue {
    private static final int MAXIMUM_BUFFER_AHEAD_PERIODS = 100;
    private int length;
    private MediaPeriodHolder loading;
    private long nextWindowSequenceNumber;
    private Object oldFrontPeriodUid;
    private long oldFrontPeriodWindowSequenceNumber;
    private MediaPeriodHolder playing;
    private MediaPeriodHolder reading;
    private int repeatMode;
    private boolean shuffleModeEnabled;
    private final Timeline.Period period = new Timeline.Period();
    private final Timeline.Window window = new Timeline.Window();
    private Timeline timeline = Timeline.EMPTY;

    public void setTimeline(Timeline timeline) {
        this.timeline = timeline;
    }

    public boolean updateRepeatMode(int repeatMode) {
        this.repeatMode = repeatMode;
        return updateForPlaybackModeChange();
    }

    public boolean updateShuffleModeEnabled(boolean shuffleModeEnabled) {
        this.shuffleModeEnabled = shuffleModeEnabled;
        return updateForPlaybackModeChange();
    }

    public boolean isLoading(MediaPeriod mediaPeriod) {
        MediaPeriodHolder mediaPeriodHolder = this.loading;
        return mediaPeriodHolder != null && mediaPeriodHolder.mediaPeriod == mediaPeriod;
    }

    public void reevaluateBuffer(long rendererPositionUs) {
        MediaPeriodHolder mediaPeriodHolder = this.loading;
        if (mediaPeriodHolder != null) {
            mediaPeriodHolder.reevaluateBuffer(rendererPositionUs);
        }
    }

    public boolean shouldLoadNextMediaPeriod() {
        MediaPeriodHolder mediaPeriodHolder = this.loading;
        return mediaPeriodHolder == null || (!mediaPeriodHolder.info.isFinal && this.loading.isFullyBuffered() && this.loading.info.durationUs != C.TIME_UNSET && this.length < 100);
    }

    public MediaPeriodInfo getNextMediaPeriodInfo(long rendererPositionUs, PlaybackInfo playbackInfo) {
        MediaPeriodHolder mediaPeriodHolder = this.loading;
        if (mediaPeriodHolder == null) {
            return getFirstMediaPeriodInfo(playbackInfo);
        }
        return getFollowingMediaPeriodInfo(mediaPeriodHolder, rendererPositionUs);
    }

    public MediaPeriod enqueueNextMediaPeriod(RendererCapabilities[] rendererCapabilities, TrackSelector trackSelector, Allocator allocator, MediaSource mediaSource, MediaPeriodInfo info) {
        MediaPeriodHolder mediaPeriodHolder = this.loading;
        long rendererPositionOffsetUs = mediaPeriodHolder == null ? info.startPositionUs : mediaPeriodHolder.getRendererOffset() + this.loading.info.durationUs;
        MediaPeriodHolder newPeriodHolder = new MediaPeriodHolder(rendererCapabilities, rendererPositionOffsetUs, trackSelector, allocator, mediaSource, info);
        if (this.loading != null) {
            Assertions.checkState(hasPlayingPeriod());
            this.loading.setNext(newPeriodHolder);
        }
        this.oldFrontPeriodUid = null;
        this.loading = newPeriodHolder;
        this.length++;
        return newPeriodHolder.mediaPeriod;
    }

    public MediaPeriodHolder getLoadingPeriod() {
        return this.loading;
    }

    public MediaPeriodHolder getPlayingPeriod() {
        return this.playing;
    }

    public MediaPeriodHolder getReadingPeriod() {
        return this.reading;
    }

    public MediaPeriodHolder getFrontPeriod() {
        return hasPlayingPeriod() ? this.playing : this.loading;
    }

    public boolean hasPlayingPeriod() {
        return this.playing != null;
    }

    public MediaPeriodHolder advanceReadingPeriod() {
        MediaPeriodHolder mediaPeriodHolder = this.reading;
        Assertions.checkState((mediaPeriodHolder == null || mediaPeriodHolder.getNext() == null) ? false : true);
        MediaPeriodHolder next = this.reading.getNext();
        this.reading = next;
        return next;
    }

    public MediaPeriodHolder advancePlayingPeriod() {
        MediaPeriodHolder mediaPeriodHolder = this.playing;
        if (mediaPeriodHolder != null) {
            if (mediaPeriodHolder == this.reading) {
                this.reading = mediaPeriodHolder.getNext();
            }
            this.playing.release();
            int i = this.length - 1;
            this.length = i;
            if (i == 0) {
                this.loading = null;
                this.oldFrontPeriodUid = this.playing.uid;
                this.oldFrontPeriodWindowSequenceNumber = this.playing.info.id.windowSequenceNumber;
            }
            this.playing = this.playing.getNext();
        } else {
            MediaPeriodHolder mediaPeriodHolder2 = this.loading;
            this.playing = mediaPeriodHolder2;
            this.reading = mediaPeriodHolder2;
        }
        return this.playing;
    }

    public boolean removeAfter(MediaPeriodHolder mediaPeriodHolder) {
        Assertions.checkState(mediaPeriodHolder != null);
        boolean removedReading = false;
        this.loading = mediaPeriodHolder;
        while (mediaPeriodHolder.getNext() != null) {
            mediaPeriodHolder = mediaPeriodHolder.getNext();
            if (mediaPeriodHolder == this.reading) {
                this.reading = this.playing;
                removedReading = true;
            }
            mediaPeriodHolder.release();
            this.length--;
        }
        this.loading.setNext(null);
        return removedReading;
    }

    public void clear(boolean keepFrontPeriodUid) {
        MediaPeriodHolder front = getFrontPeriod();
        if (front != null) {
            this.oldFrontPeriodUid = keepFrontPeriodUid ? front.uid : null;
            this.oldFrontPeriodWindowSequenceNumber = front.info.id.windowSequenceNumber;
            front.release();
            removeAfter(front);
        } else if (!keepFrontPeriodUid) {
            this.oldFrontPeriodUid = null;
        }
        this.playing = null;
        this.loading = null;
        this.reading = null;
        this.length = 0;
    }

    public boolean updateQueuedPeriods(MediaSource.MediaPeriodId playingPeriodId, long rendererPositionUs) {
        int periodIndex = this.timeline.getIndexOfPeriod(playingPeriodId.periodUid);
        MediaPeriodHolder previousPeriodHolder = null;
        for (MediaPeriodHolder periodHolder = getFrontPeriod(); periodHolder != null; periodHolder = periodHolder.getNext()) {
            if (previousPeriodHolder == null) {
                long previousDurationUs = periodHolder.info.durationUs;
                periodHolder.info = getUpdatedMediaPeriodInfo(periodHolder.info);
                if (!canKeepAfterMediaPeriodHolder(periodHolder, previousDurationUs)) {
                    return true ^ removeAfter(periodHolder);
                }
            } else {
                if (periodIndex == -1 || !periodHolder.uid.equals(this.timeline.getUidOfPeriod(periodIndex))) {
                    return true ^ removeAfter(previousPeriodHolder);
                }
                MediaPeriodInfo periodInfo = getFollowingMediaPeriodInfo(previousPeriodHolder, rendererPositionUs);
                if (periodInfo == null) {
                    return true ^ removeAfter(previousPeriodHolder);
                }
                periodHolder.info = getUpdatedMediaPeriodInfo(periodHolder.info);
                if (!canKeepMediaPeriodHolder(periodHolder, periodInfo)) {
                    return true ^ removeAfter(previousPeriodHolder);
                }
                if (!canKeepAfterMediaPeriodHolder(periodHolder, periodInfo.durationUs)) {
                    return true ^ removeAfter(periodHolder);
                }
            }
            if (periodHolder.info.isLastInTimelinePeriod) {
                periodIndex = this.timeline.getNextPeriodIndex(periodIndex, this.period, this.window, this.repeatMode, this.shuffleModeEnabled);
            }
            previousPeriodHolder = periodHolder;
        }
        return true;
    }

    public MediaPeriodInfo getUpdatedMediaPeriodInfo(MediaPeriodInfo info) {
        long durationUs;
        MediaSource.MediaPeriodId id = info.id;
        boolean isLastInPeriod = isLastInPeriod(id);
        boolean isLastInTimeline = isLastInTimeline(id, isLastInPeriod);
        this.timeline.getPeriodByUid(info.id.periodUid, this.period);
        if (id.isAd()) {
            durationUs = this.period.getAdDurationUs(id.adGroupIndex, id.adIndexInAdGroup);
        } else {
            durationUs = (id.endPositionUs == C.TIME_UNSET || id.endPositionUs == Long.MIN_VALUE) ? this.period.getDurationUs() : id.endPositionUs;
        }
        return new MediaPeriodInfo(id, info.startPositionUs, info.contentPositionUs, durationUs, isLastInPeriod, isLastInTimeline);
    }

    public MediaSource.MediaPeriodId resolveMediaPeriodIdForAds(Object periodUid, long positionUs) {
        long windowSequenceNumber = resolvePeriodIndexToWindowSequenceNumber(periodUid);
        return resolveMediaPeriodIdForAds(periodUid, positionUs, windowSequenceNumber);
    }

    private MediaSource.MediaPeriodId resolveMediaPeriodIdForAds(Object periodUid, long positionUs, long windowSequenceNumber) {
        this.timeline.getPeriodByUid(periodUid, this.period);
        int adGroupIndex = this.period.getAdGroupIndexForPositionUs(positionUs);
        if (adGroupIndex == -1) {
            int nextAdGroupIndex = this.period.getAdGroupIndexAfterPositionUs(positionUs);
            long endPositionUs = nextAdGroupIndex == -1 ? -9223372036854775807L : this.period.getAdGroupTimeUs(nextAdGroupIndex);
            return new MediaSource.MediaPeriodId(periodUid, windowSequenceNumber, endPositionUs);
        }
        int adIndexInAdGroup = this.period.getFirstAdIndexToPlay(adGroupIndex);
        return new MediaSource.MediaPeriodId(periodUid, adGroupIndex, adIndexInAdGroup, windowSequenceNumber);
    }

    private long resolvePeriodIndexToWindowSequenceNumber(Object periodUid) {
        int oldFrontPeriodIndex;
        int windowIndex = this.timeline.getPeriodByUid(periodUid, this.period).windowIndex;
        Object obj = this.oldFrontPeriodUid;
        if (obj != null && (oldFrontPeriodIndex = this.timeline.getIndexOfPeriod(obj)) != -1) {
            int oldFrontWindowIndex = this.timeline.getPeriod(oldFrontPeriodIndex, this.period).windowIndex;
            if (oldFrontWindowIndex == windowIndex) {
                return this.oldFrontPeriodWindowSequenceNumber;
            }
        }
        for (MediaPeriodHolder mediaPeriodHolder = getFrontPeriod(); mediaPeriodHolder != null; mediaPeriodHolder = mediaPeriodHolder.getNext()) {
            if (mediaPeriodHolder.uid.equals(periodUid)) {
                return mediaPeriodHolder.info.id.windowSequenceNumber;
            }
        }
        for (MediaPeriodHolder mediaPeriodHolder2 = getFrontPeriod(); mediaPeriodHolder2 != null; mediaPeriodHolder2 = mediaPeriodHolder2.getNext()) {
            int indexOfHolderInTimeline = this.timeline.getIndexOfPeriod(mediaPeriodHolder2.uid);
            if (indexOfHolderInTimeline != -1) {
                int holderWindowIndex = this.timeline.getPeriod(indexOfHolderInTimeline, this.period).windowIndex;
                if (holderWindowIndex == windowIndex) {
                    return mediaPeriodHolder2.info.id.windowSequenceNumber;
                }
            }
        }
        long j = this.nextWindowSequenceNumber;
        this.nextWindowSequenceNumber = 1 + j;
        return j;
    }

    private boolean canKeepMediaPeriodHolder(MediaPeriodHolder periodHolder, MediaPeriodInfo info) {
        MediaPeriodInfo periodHolderInfo = periodHolder.info;
        return periodHolderInfo.startPositionUs == info.startPositionUs && periodHolderInfo.id.equals(info.id);
    }

    private boolean canKeepAfterMediaPeriodHolder(MediaPeriodHolder periodHolder, long previousDurationUs) {
        return previousDurationUs == C.TIME_UNSET || previousDurationUs == periodHolder.info.durationUs;
    }

    private boolean updateForPlaybackModeChange() {
        MediaPeriodHolder lastValidPeriodHolder = getFrontPeriod();
        if (lastValidPeriodHolder == null) {
            return true;
        }
        int nextPeriodIndex = this.timeline.getIndexOfPeriod(lastValidPeriodHolder.uid);
        while (true) {
            int currentPeriodIndex = nextPeriodIndex;
            nextPeriodIndex = this.timeline.getNextPeriodIndex(currentPeriodIndex, this.period, this.window, this.repeatMode, this.shuffleModeEnabled);
            while (lastValidPeriodHolder.getNext() != null && !lastValidPeriodHolder.info.isLastInTimelinePeriod) {
                lastValidPeriodHolder = lastValidPeriodHolder.getNext();
            }
            MediaPeriodHolder nextMediaPeriodHolder = lastValidPeriodHolder.getNext();
            if (nextPeriodIndex == -1 || nextMediaPeriodHolder == null) {
                break;
            }
            int nextPeriodHolderPeriodIndex = this.timeline.getIndexOfPeriod(nextMediaPeriodHolder.uid);
            if (nextPeriodHolderPeriodIndex != nextPeriodIndex) {
                break;
            }
            lastValidPeriodHolder = nextMediaPeriodHolder;
        }
        boolean readingPeriodRemoved = removeAfter(lastValidPeriodHolder);
        lastValidPeriodHolder.info = getUpdatedMediaPeriodInfo(lastValidPeriodHolder.info);
        return (readingPeriodRemoved && hasPlayingPeriod()) ? false : true;
    }

    private MediaPeriodInfo getFirstMediaPeriodInfo(PlaybackInfo playbackInfo) {
        return getMediaPeriodInfo(playbackInfo.periodId, playbackInfo.contentPositionUs, playbackInfo.startPositionUs);
    }

    private MediaPeriodInfo getFollowingMediaPeriodInfo(MediaPeriodHolder mediaPeriodHolder, long rendererPositionUs) {
        long startPositionUs;
        long windowSequenceNumber;
        long startPositionUs2;
        Object nextPeriodUid;
        long windowSequenceNumber2;
        MediaPeriodInfo mediaPeriodInfo = mediaPeriodHolder.info;
        long bufferedDurationUs = (mediaPeriodHolder.getRendererOffset() + mediaPeriodInfo.durationUs) - rendererPositionUs;
        if (mediaPeriodInfo.isLastInTimelinePeriod) {
            int currentPeriodIndex = this.timeline.getIndexOfPeriod(mediaPeriodInfo.id.periodUid);
            int nextPeriodIndex = this.timeline.getNextPeriodIndex(currentPeriodIndex, this.period, this.window, this.repeatMode, this.shuffleModeEnabled);
            if (nextPeriodIndex == -1) {
                return null;
            }
            int nextWindowIndex = this.timeline.getPeriod(nextPeriodIndex, this.period, true).windowIndex;
            Object nextPeriodUid2 = this.period.uid;
            long windowSequenceNumber3 = mediaPeriodInfo.id.windowSequenceNumber;
            if (this.timeline.getWindow(nextWindowIndex, this.window).firstPeriodIndex == nextPeriodIndex) {
                Pair<Object, Long> defaultPosition = this.timeline.getPeriodPosition(this.window, this.period, nextWindowIndex, C.TIME_UNSET, Math.max(0L, bufferedDurationUs));
                if (defaultPosition == null) {
                    return null;
                }
                Object nextPeriodUid3 = defaultPosition.first;
                startPositionUs2 = ((Long) defaultPosition.second).longValue();
                MediaPeriodHolder nextMediaPeriodHolder = mediaPeriodHolder.getNext();
                if (nextMediaPeriodHolder != null && nextMediaPeriodHolder.uid.equals(nextPeriodUid3)) {
                    long windowSequenceNumber4 = nextMediaPeriodHolder.info.id.windowSequenceNumber;
                    nextPeriodUid = nextPeriodUid3;
                    windowSequenceNumber2 = windowSequenceNumber4;
                } else {
                    nextPeriodUid = nextPeriodUid3;
                    windowSequenceNumber2 = this.nextWindowSequenceNumber;
                    this.nextWindowSequenceNumber = windowSequenceNumber2 + 1;
                }
                windowSequenceNumber = windowSequenceNumber2;
            } else {
                windowSequenceNumber = windowSequenceNumber3;
                startPositionUs2 = 0;
                nextPeriodUid = nextPeriodUid2;
            }
            long j = startPositionUs2;
            MediaSource.MediaPeriodId periodId = resolveMediaPeriodIdForAds(nextPeriodUid, j, windowSequenceNumber);
            return getMediaPeriodInfo(periodId, j, startPositionUs2);
        }
        MediaSource.MediaPeriodId currentPeriodId = mediaPeriodInfo.id;
        this.timeline.getPeriodByUid(currentPeriodId.periodUid, this.period);
        if (!currentPeriodId.isAd()) {
            int nextAdGroupIndex = this.period.getAdGroupIndexForPositionUs(mediaPeriodInfo.id.endPositionUs);
            if (nextAdGroupIndex == -1) {
                return getMediaPeriodInfoForContent(currentPeriodId.periodUid, mediaPeriodInfo.durationUs, currentPeriodId.windowSequenceNumber);
            }
            int adIndexInAdGroup = this.period.getFirstAdIndexToPlay(nextAdGroupIndex);
            if (!this.period.isAdAvailable(nextAdGroupIndex, adIndexInAdGroup)) {
                return null;
            }
            return getMediaPeriodInfoForAd(currentPeriodId.periodUid, nextAdGroupIndex, adIndexInAdGroup, mediaPeriodInfo.durationUs, currentPeriodId.windowSequenceNumber);
        }
        int adGroupIndex = currentPeriodId.adGroupIndex;
        int adCountInCurrentAdGroup = this.period.getAdCountInAdGroup(adGroupIndex);
        if (adCountInCurrentAdGroup == -1) {
            return null;
        }
        int nextAdIndexInAdGroup = this.period.getNextAdIndexToPlay(adGroupIndex, currentPeriodId.adIndexInAdGroup);
        if (nextAdIndexInAdGroup < adCountInCurrentAdGroup) {
            if (this.period.isAdAvailable(adGroupIndex, nextAdIndexInAdGroup)) {
                return getMediaPeriodInfoForAd(currentPeriodId.periodUid, adGroupIndex, nextAdIndexInAdGroup, mediaPeriodInfo.contentPositionUs, currentPeriodId.windowSequenceNumber);
            }
            return null;
        }
        long startPositionUs3 = mediaPeriodInfo.contentPositionUs;
        if (this.period.getAdGroupCount() == 1 && this.period.getAdGroupTimeUs(0) == 0) {
            Timeline timeline = this.timeline;
            Timeline.Window window = this.window;
            Timeline.Period period = this.period;
            Pair<Object, Long> defaultPosition2 = timeline.getPeriodPosition(window, period, period.windowIndex, C.TIME_UNSET, Math.max(0L, bufferedDurationUs));
            if (defaultPosition2 == null) {
                return null;
            }
            long startPositionUs4 = ((Long) defaultPosition2.second).longValue();
            startPositionUs = startPositionUs4;
        } else {
            startPositionUs = startPositionUs3;
        }
        return getMediaPeriodInfoForContent(currentPeriodId.periodUid, startPositionUs, currentPeriodId.windowSequenceNumber);
    }

    private MediaPeriodInfo getMediaPeriodInfo(MediaSource.MediaPeriodId id, long contentPositionUs, long startPositionUs) {
        this.timeline.getPeriodByUid(id.periodUid, this.period);
        if (id.isAd()) {
            if (!this.period.isAdAvailable(id.adGroupIndex, id.adIndexInAdGroup)) {
                return null;
            }
            return getMediaPeriodInfoForAd(id.periodUid, id.adGroupIndex, id.adIndexInAdGroup, contentPositionUs, id.windowSequenceNumber);
        }
        return getMediaPeriodInfoForContent(id.periodUid, startPositionUs, id.windowSequenceNumber);
    }

    private MediaPeriodInfo getMediaPeriodInfoForAd(Object periodUid, int adGroupIndex, int adIndexInAdGroup, long contentPositionUs, long windowSequenceNumber) {
        MediaSource.MediaPeriodId id = new MediaSource.MediaPeriodId(periodUid, adGroupIndex, adIndexInAdGroup, windowSequenceNumber);
        long durationUs = this.timeline.getPeriodByUid(id.periodUid, this.period).getAdDurationUs(id.adGroupIndex, id.adIndexInAdGroup);
        long startPositionUs = adIndexInAdGroup == this.period.getFirstAdIndexToPlay(adGroupIndex) ? this.period.getAdResumePositionUs() : 0L;
        return new MediaPeriodInfo(id, startPositionUs, contentPositionUs, durationUs, false, false);
    }

    private MediaPeriodInfo getMediaPeriodInfoForContent(Object periodUid, long startPositionUs, long windowSequenceNumber) {
        long adGroupTimeUs;
        int nextAdGroupIndex = this.period.getAdGroupIndexAfterPositionUs(startPositionUs);
        if (nextAdGroupIndex == -1) {
            adGroupTimeUs = -9223372036854775807L;
        } else {
            adGroupTimeUs = this.period.getAdGroupTimeUs(nextAdGroupIndex);
        }
        long endPositionUs = adGroupTimeUs;
        MediaSource.MediaPeriodId id = new MediaSource.MediaPeriodId(periodUid, windowSequenceNumber, endPositionUs);
        boolean isLastInPeriod = isLastInPeriod(id);
        boolean isLastInTimeline = isLastInTimeline(id, isLastInPeriod);
        long durationUs = (endPositionUs == C.TIME_UNSET || endPositionUs == Long.MIN_VALUE) ? this.period.durationUs : endPositionUs;
        return new MediaPeriodInfo(id, startPositionUs, C.TIME_UNSET, durationUs, isLastInPeriod, isLastInTimeline);
    }

    private boolean isLastInPeriod(MediaSource.MediaPeriodId id) {
        return !id.isAd() && id.endPositionUs == C.TIME_UNSET;
    }

    private boolean isLastInTimeline(MediaSource.MediaPeriodId id, boolean isLastMediaPeriodInPeriod) {
        int periodIndex = this.timeline.getIndexOfPeriod(id.periodUid);
        int windowIndex = this.timeline.getPeriod(periodIndex, this.period).windowIndex;
        return !this.timeline.getWindow(windowIndex, this.window).isDynamic && this.timeline.isLastPeriod(periodIndex, this.period, this.window, this.repeatMode, this.shuffleModeEnabled) && isLastMediaPeriodInPeriod;
    }
}
