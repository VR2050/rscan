package com.google.android.exoplayer2.offline;

/* JADX INFO: loaded from: classes2.dex */
public final class StreamKey implements Comparable<StreamKey> {
    public final int groupIndex;
    public final int periodIndex;
    public final int trackIndex;

    public StreamKey(int groupIndex, int trackIndex) {
        this(0, groupIndex, trackIndex);
    }

    public StreamKey(int periodIndex, int groupIndex, int trackIndex) {
        this.periodIndex = periodIndex;
        this.groupIndex = groupIndex;
        this.trackIndex = trackIndex;
    }

    public String toString() {
        return this.periodIndex + "." + this.groupIndex + "." + this.trackIndex;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        StreamKey that = (StreamKey) o;
        return this.periodIndex == that.periodIndex && this.groupIndex == that.groupIndex && this.trackIndex == that.trackIndex;
    }

    public int hashCode() {
        int result = this.periodIndex;
        return (((result * 31) + this.groupIndex) * 31) + this.trackIndex;
    }

    @Override // java.lang.Comparable
    public int compareTo(StreamKey o) {
        int result = this.periodIndex - o.periodIndex;
        if (result == 0) {
            int result2 = this.groupIndex - o.groupIndex;
            if (result2 == 0) {
                return this.trackIndex - o.trackIndex;
            }
            return result2;
        }
        return result;
    }
}
