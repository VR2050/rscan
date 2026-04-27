package com.googlecode.mp4parser.authoring;

import com.coremedia.iso.IsoFile;
import com.coremedia.iso.boxes.CompositionTimeToSample;
import com.coremedia.iso.boxes.Container;
import com.coremedia.iso.boxes.SampleDependencyTypeBox;
import com.coremedia.iso.boxes.SampleDescriptionBox;
import com.coremedia.iso.boxes.SubSampleInformationBox;
import com.coremedia.iso.boxes.TrackBox;
import com.googlecode.mp4parser.BasicContainer;
import com.googlecode.mp4parser.boxes.mp4.samplegrouping.GroupEntry;
import com.googlecode.mp4parser.boxes.mp4.samplegrouping.SampleGroupDescriptionBox;
import com.googlecode.mp4parser.boxes.mp4.samplegrouping.SampleToGroupBox;
import com.googlecode.mp4parser.util.CastUtils;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class Mp4TrackImpl extends AbstractTrack {
    private List<CompositionTimeToSample.Entry> compositionTimeEntries;
    private long[] decodingTimes;
    IsoFile[] fragments;
    private String handler;
    private List<SampleDependencyTypeBox.Entry> sampleDependencies;
    private SampleDescriptionBox sampleDescriptionBox;
    private List<Sample> samples;
    private SubSampleInformationBox subSampleInformationBox;
    private long[] syncSamples;
    TrackBox trackBox;
    private TrackMetaData trackMetaData;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Removed duplicated region for block: B:95:0x039a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Mp4TrackImpl(java.lang.String r43, com.coremedia.iso.boxes.TrackBox r44, com.coremedia.iso.IsoFile... r45) {
        /*
            Method dump skipped, instruction units count: 1285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.googlecode.mp4parser.authoring.Mp4TrackImpl.<init>(java.lang.String, com.coremedia.iso.boxes.TrackBox, com.coremedia.iso.IsoFile[]):void");
    }

    private Map<GroupEntry, long[]> getSampleGroups(List<SampleGroupDescriptionBox> sgdbs, List<SampleToGroupBox> sbgps, Map<GroupEntry, long[]> sampleGroups) {
        for (SampleGroupDescriptionBox sgdb : sgdbs) {
            boolean found = false;
            Iterator<SampleToGroupBox> it = sbgps.iterator();
            while (true) {
                int i = 0;
                if (!it.hasNext()) {
                    break;
                }
                SampleToGroupBox sbgp = it.next();
                if (sbgp.getGroupingType().equals(sgdb.getGroupEntries().get(0).getType())) {
                    boolean found2 = true;
                    int sampleNum = 0;
                    for (SampleToGroupBox.Entry entry : sbgp.getEntries()) {
                        if (entry.getGroupDescriptionIndex() > 0) {
                            GroupEntry groupEntry = sgdb.getGroupEntries().get(entry.getGroupDescriptionIndex() - 1);
                            long[] samples = sampleGroups.get(groupEntry);
                            if (samples == null) {
                                samples = new long[i];
                            }
                            long[] nuSamples = new long[CastUtils.l2i(entry.getSampleCount()) + samples.length];
                            System.arraycopy(samples, i, nuSamples, i, samples.length);
                            int i2 = 0;
                            while (i2 < entry.getSampleCount()) {
                                nuSamples[samples.length + i2] = sampleNum + i2;
                                i2++;
                                found2 = found2;
                            }
                            sampleGroups.put(groupEntry, nuSamples);
                        }
                        sampleNum = (int) (((long) sampleNum) + entry.getSampleCount());
                        found2 = found2;
                        i = 0;
                    }
                    found = found2;
                }
            }
            if (!found) {
                throw new RuntimeException("Could not find SampleToGroupBox for " + sgdb.getGroupEntries().get(0).getType() + ".");
            }
        }
        return sampleGroups;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        Container c = this.trackBox.getParent();
        if (c instanceof BasicContainer) {
            ((BasicContainer) c).close();
        }
        for (IsoFile fragment : this.fragments) {
            fragment.close();
        }
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public List<Sample> getSamples() {
        return this.samples;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public synchronized long[] getSampleDurations() {
        return this.decodingTimes;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public SampleDescriptionBox getSampleDescriptionBox() {
        return this.sampleDescriptionBox;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public List<CompositionTimeToSample.Entry> getCompositionTimeEntries() {
        return this.compositionTimeEntries;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public long[] getSyncSamples() {
        if (this.syncSamples.length == this.samples.size()) {
            return null;
        }
        return this.syncSamples;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public List<SampleDependencyTypeBox.Entry> getSampleDependencies() {
        return this.sampleDependencies;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public TrackMetaData getTrackMetaData() {
        return this.trackMetaData;
    }

    @Override // com.googlecode.mp4parser.authoring.Track
    public String getHandler() {
        return this.handler;
    }

    @Override // com.googlecode.mp4parser.authoring.AbstractTrack, com.googlecode.mp4parser.authoring.Track
    public SubSampleInformationBox getSubsampleInformationBox() {
        return this.subSampleInformationBox;
    }
}
