package com.google.android.exoplayer2.metadata.scte35;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.util.ParsableByteArray;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class SpliceScheduleCommand extends SpliceCommand {
    public static final Parcelable.Creator<SpliceScheduleCommand> CREATOR = new Parcelable.Creator<SpliceScheduleCommand>() { // from class: com.google.android.exoplayer2.metadata.scte35.SpliceScheduleCommand.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public SpliceScheduleCommand createFromParcel(Parcel in) {
            return new SpliceScheduleCommand(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public SpliceScheduleCommand[] newArray(int size) {
            return new SpliceScheduleCommand[size];
        }
    };
    public final List<Event> events;

    public static final class Event {
        public final boolean autoReturn;
        public final int availNum;
        public final int availsExpected;
        public final long breakDurationUs;
        public final List<ComponentSplice> componentSpliceList;
        public final boolean outOfNetworkIndicator;
        public final boolean programSpliceFlag;
        public final boolean spliceEventCancelIndicator;
        public final long spliceEventId;
        public final int uniqueProgramId;
        public final long utcSpliceTime;

        private Event(long spliceEventId, boolean spliceEventCancelIndicator, boolean outOfNetworkIndicator, boolean programSpliceFlag, List<ComponentSplice> componentSpliceList, long utcSpliceTime, boolean autoReturn, long breakDurationUs, int uniqueProgramId, int availNum, int availsExpected) {
            this.spliceEventId = spliceEventId;
            this.spliceEventCancelIndicator = spliceEventCancelIndicator;
            this.outOfNetworkIndicator = outOfNetworkIndicator;
            this.programSpliceFlag = programSpliceFlag;
            this.componentSpliceList = Collections.unmodifiableList(componentSpliceList);
            this.utcSpliceTime = utcSpliceTime;
            this.autoReturn = autoReturn;
            this.breakDurationUs = breakDurationUs;
            this.uniqueProgramId = uniqueProgramId;
            this.availNum = availNum;
            this.availsExpected = availsExpected;
        }

        private Event(Parcel in) {
            this.spliceEventId = in.readLong();
            this.spliceEventCancelIndicator = in.readByte() == 1;
            this.outOfNetworkIndicator = in.readByte() == 1;
            this.programSpliceFlag = in.readByte() == 1;
            int componentSpliceListLength = in.readInt();
            ArrayList<ComponentSplice> componentSpliceList = new ArrayList<>(componentSpliceListLength);
            for (int i = 0; i < componentSpliceListLength; i++) {
                componentSpliceList.add(ComponentSplice.createFromParcel(in));
            }
            this.componentSpliceList = Collections.unmodifiableList(componentSpliceList);
            this.utcSpliceTime = in.readLong();
            this.autoReturn = in.readByte() == 1;
            this.breakDurationUs = in.readLong();
            this.uniqueProgramId = in.readInt();
            this.availNum = in.readInt();
            this.availsExpected = in.readInt();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static Event parseFromSection(ParsableByteArray sectionData) {
            boolean outOfNetworkIndicator;
            boolean programSpliceFlag;
            long utcSpliceTime;
            ArrayList<ComponentSplice> componentSplices;
            int uniqueProgramId;
            int availNum;
            int availsExpected;
            boolean autoReturn;
            long breakDurationUs;
            long spliceEventId = sectionData.readUnsignedInt();
            boolean spliceEventCancelIndicator = (sectionData.readUnsignedByte() & 128) != 0;
            long utcSpliceTime2 = C.TIME_UNSET;
            ArrayList<ComponentSplice> componentSplices2 = new ArrayList<>();
            boolean autoReturn2 = false;
            long breakDurationUs2 = C.TIME_UNSET;
            if (spliceEventCancelIndicator) {
                outOfNetworkIndicator = false;
                programSpliceFlag = false;
                utcSpliceTime = -9223372036854775807L;
                componentSplices = componentSplices2;
                uniqueProgramId = 0;
                availNum = 0;
                availsExpected = 0;
                autoReturn = false;
                breakDurationUs = -9223372036854775807L;
            } else {
                int headerByte = sectionData.readUnsignedByte();
                boolean outOfNetworkIndicator2 = (headerByte & 128) != 0;
                boolean programSpliceFlag2 = (headerByte & 64) != 0;
                boolean durationFlag = (headerByte & 32) != 0;
                if (programSpliceFlag2) {
                    utcSpliceTime2 = sectionData.readUnsignedInt();
                }
                if (programSpliceFlag2) {
                    outOfNetworkIndicator = outOfNetworkIndicator2;
                    programSpliceFlag = programSpliceFlag2;
                    utcSpliceTime = utcSpliceTime2;
                } else {
                    int componentCount = sectionData.readUnsignedByte();
                    ArrayList<ComponentSplice> componentSplices3 = new ArrayList<>(componentCount);
                    int i = 0;
                    while (i < componentCount) {
                        boolean outOfNetworkIndicator3 = outOfNetworkIndicator2;
                        int componentTag = sectionData.readUnsignedByte();
                        boolean programSpliceFlag3 = programSpliceFlag2;
                        long componentUtcSpliceTime = sectionData.readUnsignedInt();
                        componentSplices3.add(new ComponentSplice(componentTag, componentUtcSpliceTime));
                        i++;
                        outOfNetworkIndicator2 = outOfNetworkIndicator3;
                        programSpliceFlag2 = programSpliceFlag3;
                        utcSpliceTime2 = utcSpliceTime2;
                        componentCount = componentCount;
                    }
                    outOfNetworkIndicator = outOfNetworkIndicator2;
                    programSpliceFlag = programSpliceFlag2;
                    utcSpliceTime = utcSpliceTime2;
                    componentSplices2 = componentSplices3;
                }
                if (durationFlag) {
                    long firstByte = sectionData.readUnsignedByte();
                    boolean autoReturn3 = (128 & firstByte) != 0;
                    long breakDuration90khz = ((1 & firstByte) << 32) | sectionData.readUnsignedInt();
                    autoReturn2 = autoReturn3;
                    breakDurationUs2 = (1000 * breakDuration90khz) / 90;
                }
                int uniqueProgramId2 = sectionData.readUnsignedShort();
                int availNum2 = sectionData.readUnsignedByte();
                int availsExpected2 = sectionData.readUnsignedByte();
                componentSplices = componentSplices2;
                uniqueProgramId = uniqueProgramId2;
                availNum = availNum2;
                availsExpected = availsExpected2;
                autoReturn = autoReturn2;
                breakDurationUs = breakDurationUs2;
            }
            return new Event(spliceEventId, spliceEventCancelIndicator, outOfNetworkIndicator, programSpliceFlag, componentSplices, utcSpliceTime, autoReturn, breakDurationUs, uniqueProgramId, availNum, availsExpected);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void writeToParcel(Parcel parcel) {
            parcel.writeLong(this.spliceEventId);
            parcel.writeByte(this.spliceEventCancelIndicator ? (byte) 1 : (byte) 0);
            parcel.writeByte(this.outOfNetworkIndicator ? (byte) 1 : (byte) 0);
            parcel.writeByte(this.programSpliceFlag ? (byte) 1 : (byte) 0);
            int size = this.componentSpliceList.size();
            parcel.writeInt(size);
            for (int i = 0; i < size; i++) {
                this.componentSpliceList.get(i).writeToParcel(parcel);
            }
            parcel.writeLong(this.utcSpliceTime);
            parcel.writeByte(this.autoReturn ? (byte) 1 : (byte) 0);
            parcel.writeLong(this.breakDurationUs);
            parcel.writeInt(this.uniqueProgramId);
            parcel.writeInt(this.availNum);
            parcel.writeInt(this.availsExpected);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static Event createFromParcel(Parcel in) {
            return new Event(in);
        }
    }

    public static final class ComponentSplice {
        public final int componentTag;
        public final long utcSpliceTime;

        private ComponentSplice(int componentTag, long utcSpliceTime) {
            this.componentTag = componentTag;
            this.utcSpliceTime = utcSpliceTime;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static ComponentSplice createFromParcel(Parcel in) {
            return new ComponentSplice(in.readInt(), in.readLong());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void writeToParcel(Parcel dest) {
            dest.writeInt(this.componentTag);
            dest.writeLong(this.utcSpliceTime);
        }
    }

    private SpliceScheduleCommand(List<Event> events) {
        this.events = Collections.unmodifiableList(events);
    }

    private SpliceScheduleCommand(Parcel in) {
        int eventsSize = in.readInt();
        ArrayList<Event> events = new ArrayList<>(eventsSize);
        for (int i = 0; i < eventsSize; i++) {
            events.add(Event.createFromParcel(in));
        }
        this.events = Collections.unmodifiableList(events);
    }

    static SpliceScheduleCommand parseFromSection(ParsableByteArray sectionData) {
        int spliceCount = sectionData.readUnsignedByte();
        ArrayList<Event> events = new ArrayList<>(spliceCount);
        for (int i = 0; i < spliceCount; i++) {
            events.add(Event.parseFromSection(sectionData));
        }
        return new SpliceScheduleCommand(events);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        int eventsSize = this.events.size();
        dest.writeInt(eventsSize);
        for (int i = 0; i < eventsSize; i++) {
            this.events.get(i).writeToParcel(dest);
        }
    }
}
