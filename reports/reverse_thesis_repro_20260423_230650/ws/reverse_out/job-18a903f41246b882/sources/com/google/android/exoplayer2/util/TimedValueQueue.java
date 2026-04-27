package com.google.android.exoplayer2.util;

import java.util.Arrays;

/* JADX INFO: loaded from: classes2.dex */
public final class TimedValueQueue<V> {
    private static final int INITIAL_BUFFER_SIZE = 10;
    private int first;
    private int size;
    private long[] timestamps;
    private V[] values;

    public TimedValueQueue() {
        this(10);
    }

    public TimedValueQueue(int i) {
        this.timestamps = new long[i];
        this.values = (V[]) newArray(i);
    }

    public synchronized void add(long timestamp, V value) {
        clearBufferOnTimeDiscontinuity(timestamp);
        doubleCapacityIfFull();
        addUnchecked(timestamp, value);
    }

    public synchronized void clear() {
        this.first = 0;
        this.size = 0;
        Arrays.fill(this.values, (Object) null);
    }

    public synchronized int size() {
        return this.size;
    }

    public synchronized V pollFloor(long timestamp) {
        return poll(timestamp, true);
    }

    public synchronized V poll(long timestamp) {
        return poll(timestamp, false);
    }

    private V poll(long timestamp, boolean onlyOlder) {
        V value = null;
        long previousTimeDiff = Long.MAX_VALUE;
        while (this.size > 0) {
            long timeDiff = timestamp - this.timestamps[this.first];
            if (timeDiff < 0 && (onlyOlder || (-timeDiff) >= previousTimeDiff)) {
                break;
            }
            previousTimeDiff = timeDiff;
            V[] vArr = this.values;
            int i = this.first;
            value = vArr[i];
            vArr[i] = null;
            this.first = (i + 1) % vArr.length;
            this.size--;
        }
        return value;
    }

    private void clearBufferOnTimeDiscontinuity(long timestamp) {
        if (this.size > 0) {
            int last = ((this.first + r0) - 1) % this.values.length;
            if (timestamp <= this.timestamps[last]) {
                clear();
            }
        }
    }

    private void doubleCapacityIfFull() {
        int length = this.values.length;
        if (this.size < length) {
            return;
        }
        int i = length * 2;
        long[] jArr = new long[i];
        V[] vArr = (V[]) newArray(i);
        int i2 = this.first;
        int i3 = length - i2;
        System.arraycopy(this.timestamps, i2, jArr, 0, i3);
        System.arraycopy(this.values, this.first, vArr, 0, i3);
        int i4 = this.first;
        if (i4 > 0) {
            System.arraycopy(this.timestamps, 0, jArr, i3, i4);
            System.arraycopy(this.values, 0, vArr, i3, this.first);
        }
        this.timestamps = jArr;
        this.values = vArr;
        this.first = 0;
    }

    private void addUnchecked(long timestamp, V value) {
        int i = this.first;
        int i2 = this.size;
        V[] vArr = this.values;
        int next = (i + i2) % vArr.length;
        this.timestamps[next] = timestamp;
        vArr[next] = value;
        this.size = i2 + 1;
    }

    private static <V> V[] newArray(int i) {
        return (V[]) new Object[i];
    }
}
