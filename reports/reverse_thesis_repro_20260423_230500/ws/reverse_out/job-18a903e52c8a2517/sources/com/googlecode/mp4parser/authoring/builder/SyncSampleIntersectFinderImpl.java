package com.googlecode.mp4parser.authoring.builder;

import com.coremedia.iso.boxes.OriginalFormatBox;
import com.coremedia.iso.boxes.sampleentry.AudioSampleEntry;
import com.coremedia.iso.boxes.sampleentry.SampleEntry;
import com.coremedia.iso.boxes.sampleentry.VisualSampleEntry;
import com.googlecode.mp4parser.authoring.Movie;
import com.googlecode.mp4parser.authoring.Track;
import com.googlecode.mp4parser.util.Math;
import com.googlecode.mp4parser.util.Path;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/* JADX INFO: loaded from: classes.dex */
public class SyncSampleIntersectFinderImpl implements FragmentIntersectionFinder {
    private static Logger LOG = Logger.getLogger(SyncSampleIntersectFinderImpl.class.getName());
    private final int minFragmentDurationSeconds;
    private Movie movie;
    private Track referenceTrack;

    public SyncSampleIntersectFinderImpl(Movie movie, Track referenceTrack, int minFragmentDurationSeconds) {
        this.movie = movie;
        this.referenceTrack = referenceTrack;
        this.minFragmentDurationSeconds = minFragmentDurationSeconds;
    }

    static String getFormat(Track track) {
        SampleEntry se = track.getSampleDescriptionBox().getSampleEntry();
        String type = se.getType();
        if (type.equals(VisualSampleEntry.TYPE_ENCRYPTED) || type.equals(AudioSampleEntry.TYPE_ENCRYPTED) || type.equals(VisualSampleEntry.TYPE_ENCRYPTED)) {
            OriginalFormatBox frma = (OriginalFormatBox) Path.getPath(se, "sinf/frma");
            return frma.getDataFormat();
        }
        return type;
    }

    @Override // com.googlecode.mp4parser.authoring.builder.FragmentIntersectionFinder
    public long[] sampleNumbers(Track track) {
        if ("vide".equals(track.getHandler())) {
            if (track.getSyncSamples() != null && track.getSyncSamples().length > 0) {
                List<long[]> times = getSyncSamplesTimestamps(this.movie, track);
                return getCommonIndices(track.getSyncSamples(), getTimes(track, this.movie), track.getTrackMetaData().getTimescale(), (long[][]) times.toArray(new long[times.size()][]));
            }
            throw new RuntimeException("Video Tracks need sync samples. Only tracks other than video may have no sync samples.");
        }
        if ("soun".equals(track.getHandler())) {
            if (this.referenceTrack == null) {
                for (Track candidate : this.movie.getTracks()) {
                    if (candidate.getSyncSamples() != null && "vide".equals(candidate.getHandler()) && candidate.getSyncSamples().length > 0) {
                        this.referenceTrack = candidate;
                    }
                }
            }
            Track track2 = this.referenceTrack;
            if (track2 != null) {
                long[] refSyncSamples = sampleNumbers(track2);
                int refSampleCount = this.referenceTrack.getSamples().size();
                long[] syncSamples = new long[refSyncSamples.length];
                long sc = 192000;
                Iterator<Track> it = this.movie.getTracks().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    Track testTrack = it.next();
                    if (getFormat(track).equals(getFormat(testTrack))) {
                        AudioSampleEntry ase = (AudioSampleEntry) testTrack.getSampleDescriptionBox().getSampleEntry();
                        if (ase.getSampleRate() < 192000) {
                            long minSampleRate = ase.getSampleRate();
                            long sc2 = testTrack.getSamples().size();
                            double stretch = sc2 / ((double) refSampleCount);
                            int refSampleCount2 = refSampleCount;
                            long samplesPerFrame = testTrack.getSampleDurations()[0];
                            int i = 0;
                            while (i < syncSamples.length) {
                                double d = (refSyncSamples[i] - 1) * stretch;
                                double stretch2 = stretch;
                                double stretch3 = samplesPerFrame;
                                long start = (long) Math.ceil(d * stretch3);
                                syncSamples[i] = start;
                                i++;
                                refSampleCount2 = refSampleCount2;
                                stretch = stretch2;
                            }
                            sc = minSampleRate;
                        }
                    }
                }
                AudioSampleEntry ase2 = (AudioSampleEntry) track.getSampleDescriptionBox().getSampleEntry();
                long samplesPerFrame2 = track.getSampleDurations()[0];
                double factor = ase2.getSampleRate() / sc;
                if (factor != Math.rint(factor)) {
                    throw new RuntimeException("Sample rates must be a multiple of the lowest sample rate to create a correct file!");
                }
                int i2 = 0;
                while (i2 < syncSamples.length) {
                    long minSampleRate2 = sc;
                    syncSamples[i2] = (long) (((syncSamples[i2] * factor) / samplesPerFrame2) + 1.0d);
                    i2++;
                    sc = minSampleRate2;
                }
                return syncSamples;
            }
            throw new RuntimeException("There was absolutely no Track with sync samples. I can't work with that!");
        }
        for (Track candidate2 : this.movie.getTracks()) {
            if (candidate2.getSyncSamples() != null && candidate2.getSyncSamples().length > 0) {
                long[] refSyncSamples2 = sampleNumbers(candidate2);
                int refSampleCount3 = candidate2.getSamples().size();
                long[] syncSamples2 = new long[refSyncSamples2.length];
                long sc3 = track.getSamples().size();
                double stretch4 = sc3 / ((double) refSampleCount3);
                for (int i3 = 0; i3 < syncSamples2.length; i3++) {
                    long start2 = ((long) Math.ceil((refSyncSamples2[i3] - 1) * stretch4)) + 1;
                    syncSamples2[i3] = start2;
                }
                return syncSamples2;
            }
        }
        throw new RuntimeException("There was absolutely no Track with sync samples. I can't work with that!");
    }

    public static List<long[]> getSyncSamplesTimestamps(Movie movie, Track track) {
        long[] currentTrackSyncSamples;
        List<long[]> times = new LinkedList<>();
        for (Track currentTrack : movie.getTracks()) {
            if (currentTrack.getHandler().equals(track.getHandler()) && (currentTrackSyncSamples = currentTrack.getSyncSamples()) != null && currentTrackSyncSamples.length > 0) {
                long[] currentTrackTimes = getTimes(currentTrack, movie);
                times.add(currentTrackTimes);
            }
        }
        return times;
    }

    public long[] getCommonIndices(long[] syncSamples, long[] syncSampleTimes, long timeScale, long[]... otherTracksTimes) {
        char c;
        List<Long> finalSampleList;
        List<Long> nuSyncSamples = new LinkedList<>();
        List<Long> nuSyncSampleTimes = new LinkedList<>();
        int i = 0;
        while (true) {
            c = 0;
            if (i >= syncSampleTimes.length) {
                break;
            }
            boolean foundInEveryRef = true;
            for (long[] times : otherTracksTimes) {
                foundInEveryRef &= Arrays.binarySearch(times, syncSampleTimes[i]) >= 0;
            }
            if (foundInEveryRef) {
                nuSyncSamples.add(Long.valueOf(syncSamples[i]));
                nuSyncSampleTimes.add(Long.valueOf(syncSampleTimes[i]));
            }
            i++;
        }
        int i2 = nuSyncSamples.size();
        if (i2 < ((double) syncSamples.length) * 0.25d) {
            String log = String.valueOf("") + String.format("%5d - Common:  [", Integer.valueOf(nuSyncSamples.size()));
            Iterator<Long> it = nuSyncSamples.iterator();
            while (it.hasNext()) {
                long l = it.next().longValue();
                log = String.valueOf(log) + String.format("%10d,", Long.valueOf(l));
                c = 0;
            }
            LOG.warning(String.valueOf(log) + "]");
            StringBuilder sb = new StringBuilder(String.valueOf(""));
            Object[] objArr = new Object[1];
            objArr[c] = Integer.valueOf(syncSamples.length);
            sb.append(String.format("%5d - In    :  [", objArr));
            String log2 = sb.toString();
            for (long l2 : syncSamples) {
                log2 = String.valueOf(log2) + String.format("%10d,", Long.valueOf(l2));
            }
            LOG.warning(String.valueOf(log2) + "]");
            LOG.warning("There are less than 25% of common sync samples in the given track.");
            throw new RuntimeException("There are less than 25% of common sync samples in the given track.");
        }
        if (nuSyncSamples.size() < ((double) syncSamples.length) * 0.5d) {
            LOG.fine("There are less than 50% of common sync samples in the given track. This is implausible but I'm ok to continue.");
        } else if (nuSyncSamples.size() < syncSamples.length) {
            LOG.finest("Common SyncSample positions vs. this tracks SyncSample positions: " + nuSyncSamples.size() + " vs. " + syncSamples.length);
        }
        List<Long> finalSampleList2 = new LinkedList<>();
        if (this.minFragmentDurationSeconds > 0) {
            long lastSyncSampleTime = -1;
            Iterator<Long> nuSyncSamplesIterator = nuSyncSamples.iterator();
            Iterator<Long> nuSyncSampleTimesIterator = nuSyncSampleTimes.iterator();
            while (nuSyncSamplesIterator.hasNext() && nuSyncSampleTimesIterator.hasNext()) {
                long curSyncSample = nuSyncSamplesIterator.next().longValue();
                long curSyncSampleTime = nuSyncSampleTimesIterator.next().longValue();
                if (lastSyncSampleTime != -1) {
                    long lastSyncSampleTime2 = lastSyncSampleTime;
                    if ((curSyncSampleTime - lastSyncSampleTime) / timeScale < this.minFragmentDurationSeconds) {
                        lastSyncSampleTime = lastSyncSampleTime2;
                    }
                }
                finalSampleList2.add(Long.valueOf(curSyncSample));
                lastSyncSampleTime = curSyncSampleTime;
            }
            finalSampleList = finalSampleList2;
        } else {
            finalSampleList = nuSyncSamples;
        }
        long[] finalSampleArray = new long[finalSampleList.size()];
        for (int i3 = 0; i3 < finalSampleArray.length; i3++) {
            finalSampleArray[i3] = finalSampleList.get(i3).longValue();
        }
        return finalSampleArray;
    }

    private static long[] getTimes(Track track, Movie m) {
        long[] syncSamples = track.getSyncSamples();
        long[] syncSampleTimes = new long[syncSamples.length];
        long currentDuration = 0;
        int currentSyncSampleIndex = 0;
        long scalingFactor = calculateTracktimesScalingFactor(m, track);
        for (int currentSample = 1; currentSample <= syncSamples[syncSamples.length - 1]; currentSample++) {
            if (currentSample == syncSamples[currentSyncSampleIndex]) {
                syncSampleTimes[currentSyncSampleIndex] = currentDuration * scalingFactor;
                currentSyncSampleIndex++;
            }
            currentDuration += track.getSampleDurations()[currentSample - 1];
        }
        return syncSampleTimes;
    }

    private static long calculateTracktimesScalingFactor(Movie m, Track track) {
        long timeScale = 1;
        for (Track track1 : m.getTracks()) {
            if (track1.getHandler().equals(track.getHandler()) && track1.getTrackMetaData().getTimescale() != track.getTrackMetaData().getTimescale()) {
                timeScale = Math.lcm(timeScale, track1.getTrackMetaData().getTimescale());
            }
        }
        return timeScale;
    }
}
