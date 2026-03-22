package androidx.work.impl.model;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.arch.core.util.Function;
import androidx.room.ColumnInfo;
import androidx.room.Embedded;
import androidx.room.Entity;
import androidx.room.Index;
import androidx.room.PrimaryKey;
import androidx.room.Relation;
import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.Data;
import androidx.work.Logger;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkInfo;
import androidx.work.WorkRequest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import p005b.p131d.p132a.p133a.C1499a;

@Entity(indices = {@Index({"schedule_requested_at"}), @Index({"period_start_time"})})
@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public final class WorkSpec {
    public static final long SCHEDULE_NOT_REQUESTED_YET = -1;
    private static final String TAG = Logger.tagWithPrefix("WorkSpec");
    public static final Function<List<WorkInfoPojo>, List<WorkInfo>> WORK_INFO_MAPPER = new Function<List<WorkInfoPojo>, List<WorkInfo>>() { // from class: androidx.work.impl.model.WorkSpec.1
        @Override // androidx.arch.core.util.Function
        public List<WorkInfo> apply(List<WorkInfoPojo> list) {
            if (list == null) {
                return null;
            }
            ArrayList arrayList = new ArrayList(list.size());
            Iterator<WorkInfoPojo> it = list.iterator();
            while (it.hasNext()) {
                arrayList.add(it.next().toWorkInfo());
            }
            return arrayList;
        }
    };

    @ColumnInfo(name = "backoff_delay_duration")
    public long backoffDelayDuration;

    @NonNull
    @ColumnInfo(name = "backoff_policy")
    public BackoffPolicy backoffPolicy;

    @NonNull
    @Embedded
    public Constraints constraints;

    @ColumnInfo(name = "flex_duration")
    public long flexDuration;

    /* renamed from: id */
    @NonNull
    @PrimaryKey
    @ColumnInfo(name = "id")
    public String f210id;

    @ColumnInfo(name = "initial_delay")
    public long initialDelay;

    @NonNull
    @ColumnInfo(name = "input")
    public Data input;

    @ColumnInfo(name = "input_merger_class_name")
    public String inputMergerClassName;

    @ColumnInfo(name = "interval_duration")
    public long intervalDuration;

    @ColumnInfo(name = "minimum_retention_duration")
    public long minimumRetentionDuration;

    @NonNull
    @ColumnInfo(name = "output")
    public Data output;

    @ColumnInfo(name = "period_start_time")
    public long periodStartTime;

    @IntRange(from = 0)
    @ColumnInfo(name = "run_attempt_count")
    public int runAttemptCount;

    @ColumnInfo(name = "run_in_foreground")
    public boolean runInForeground;

    @ColumnInfo(name = "schedule_requested_at")
    public long scheduleRequestedAt;

    @NonNull
    @ColumnInfo(name = "state")
    public WorkInfo.State state;

    @NonNull
    @ColumnInfo(name = "worker_class_name")
    public String workerClassName;

    public static class IdAndState {

        /* renamed from: id */
        @ColumnInfo(name = "id")
        public String f211id;

        @ColumnInfo(name = "state")
        public WorkInfo.State state;

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof IdAndState)) {
                return false;
            }
            IdAndState idAndState = (IdAndState) obj;
            if (this.state != idAndState.state) {
                return false;
            }
            return this.f211id.equals(idAndState.f211id);
        }

        public int hashCode() {
            return this.state.hashCode() + (this.f211id.hashCode() * 31);
        }
    }

    public static class WorkInfoPojo {

        /* renamed from: id */
        @ColumnInfo(name = "id")
        public String f212id;

        @ColumnInfo(name = "output")
        public Data output;

        @Relation(entity = WorkProgress.class, entityColumn = "work_spec_id", parentColumn = "id", projection = {"progress"})
        public List<Data> progress;

        @ColumnInfo(name = "run_attempt_count")
        public int runAttemptCount;

        @ColumnInfo(name = "state")
        public WorkInfo.State state;

        @Relation(entity = WorkTag.class, entityColumn = "work_spec_id", parentColumn = "id", projection = {"tag"})
        public List<String> tags;

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof WorkInfoPojo)) {
                return false;
            }
            WorkInfoPojo workInfoPojo = (WorkInfoPojo) obj;
            if (this.runAttemptCount != workInfoPojo.runAttemptCount) {
                return false;
            }
            String str = this.f212id;
            if (str == null ? workInfoPojo.f212id != null : !str.equals(workInfoPojo.f212id)) {
                return false;
            }
            if (this.state != workInfoPojo.state) {
                return false;
            }
            Data data = this.output;
            if (data == null ? workInfoPojo.output != null : !data.equals(workInfoPojo.output)) {
                return false;
            }
            List<String> list = this.tags;
            if (list == null ? workInfoPojo.tags != null : !list.equals(workInfoPojo.tags)) {
                return false;
            }
            List<Data> list2 = this.progress;
            List<Data> list3 = workInfoPojo.progress;
            return list2 != null ? list2.equals(list3) : list3 == null;
        }

        public int hashCode() {
            String str = this.f212id;
            int hashCode = (str != null ? str.hashCode() : 0) * 31;
            WorkInfo.State state = this.state;
            int hashCode2 = (hashCode + (state != null ? state.hashCode() : 0)) * 31;
            Data data = this.output;
            int hashCode3 = (((hashCode2 + (data != null ? data.hashCode() : 0)) * 31) + this.runAttemptCount) * 31;
            List<String> list = this.tags;
            int hashCode4 = (hashCode3 + (list != null ? list.hashCode() : 0)) * 31;
            List<Data> list2 = this.progress;
            return hashCode4 + (list2 != null ? list2.hashCode() : 0);
        }

        @NonNull
        public WorkInfo toWorkInfo() {
            List<Data> list = this.progress;
            return new WorkInfo(UUID.fromString(this.f212id), this.state, this.output, this.tags, (list == null || list.isEmpty()) ? Data.EMPTY : this.progress.get(0), this.runAttemptCount);
        }
    }

    public WorkSpec(@NonNull String str, @NonNull String str2) {
        this.state = WorkInfo.State.ENQUEUED;
        Data data = Data.EMPTY;
        this.input = data;
        this.output = data;
        this.constraints = Constraints.NONE;
        this.backoffPolicy = BackoffPolicy.EXPONENTIAL;
        this.backoffDelayDuration = WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS;
        this.scheduleRequestedAt = -1L;
        this.f210id = str;
        this.workerClassName = str2;
    }

    public long calculateNextRunTime() {
        long j2;
        long j3;
        if (isBackedOff()) {
            long scalb = this.backoffPolicy == BackoffPolicy.LINEAR ? this.backoffDelayDuration * this.runAttemptCount : (long) Math.scalb(this.backoffDelayDuration, this.runAttemptCount - 1);
            j3 = this.periodStartTime;
            j2 = Math.min(WorkRequest.MAX_BACKOFF_MILLIS, scalb);
        } else {
            if (isPeriodic()) {
                long currentTimeMillis = System.currentTimeMillis();
                long j4 = this.periodStartTime;
                long j5 = j4 == 0 ? currentTimeMillis + this.initialDelay : j4;
                long j6 = this.flexDuration;
                long j7 = this.intervalDuration;
                if (j6 != j7) {
                    return j5 + j7 + (j4 == 0 ? j6 * (-1) : 0L);
                }
                return j5 + (j4 != 0 ? j7 : 0L);
            }
            j2 = this.periodStartTime;
            if (j2 == 0) {
                j2 = System.currentTimeMillis();
            }
            j3 = this.initialDelay;
        }
        return j2 + j3;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof WorkSpec)) {
            return false;
        }
        WorkSpec workSpec = (WorkSpec) obj;
        if (this.initialDelay != workSpec.initialDelay || this.intervalDuration != workSpec.intervalDuration || this.flexDuration != workSpec.flexDuration || this.runAttemptCount != workSpec.runAttemptCount || this.backoffDelayDuration != workSpec.backoffDelayDuration || this.periodStartTime != workSpec.periodStartTime || this.minimumRetentionDuration != workSpec.minimumRetentionDuration || this.scheduleRequestedAt != workSpec.scheduleRequestedAt || this.runInForeground != workSpec.runInForeground || !this.f210id.equals(workSpec.f210id) || this.state != workSpec.state || !this.workerClassName.equals(workSpec.workerClassName)) {
            return false;
        }
        String str = this.inputMergerClassName;
        if (str == null ? workSpec.inputMergerClassName == null : str.equals(workSpec.inputMergerClassName)) {
            return this.input.equals(workSpec.input) && this.output.equals(workSpec.output) && this.constraints.equals(workSpec.constraints) && this.backoffPolicy == workSpec.backoffPolicy;
        }
        return false;
    }

    public boolean hasConstraints() {
        return !Constraints.NONE.equals(this.constraints);
    }

    public int hashCode() {
        int m598T = C1499a.m598T(this.workerClassName, (this.state.hashCode() + (this.f210id.hashCode() * 31)) * 31, 31);
        String str = this.inputMergerClassName;
        int hashCode = (this.output.hashCode() + ((this.input.hashCode() + ((m598T + (str != null ? str.hashCode() : 0)) * 31)) * 31)) * 31;
        long j2 = this.initialDelay;
        int i2 = (hashCode + ((int) (j2 ^ (j2 >>> 32)))) * 31;
        long j3 = this.intervalDuration;
        int i3 = (i2 + ((int) (j3 ^ (j3 >>> 32)))) * 31;
        long j4 = this.flexDuration;
        int hashCode2 = (this.backoffPolicy.hashCode() + ((((this.constraints.hashCode() + ((i3 + ((int) (j4 ^ (j4 >>> 32)))) * 31)) * 31) + this.runAttemptCount) * 31)) * 31;
        long j5 = this.backoffDelayDuration;
        int i4 = (hashCode2 + ((int) (j5 ^ (j5 >>> 32)))) * 31;
        long j6 = this.periodStartTime;
        int i5 = (i4 + ((int) (j6 ^ (j6 >>> 32)))) * 31;
        long j7 = this.minimumRetentionDuration;
        int i6 = (i5 + ((int) (j7 ^ (j7 >>> 32)))) * 31;
        long j8 = this.scheduleRequestedAt;
        return ((i6 + ((int) (j8 ^ (j8 >>> 32)))) * 31) + (this.runInForeground ? 1 : 0);
    }

    public boolean isBackedOff() {
        return this.state == WorkInfo.State.ENQUEUED && this.runAttemptCount > 0;
    }

    public boolean isPeriodic() {
        return this.intervalDuration != 0;
    }

    public void setBackoffDelayDuration(long j2) {
        if (j2 > WorkRequest.MAX_BACKOFF_MILLIS) {
            Logger.get().warning(TAG, "Backoff delay duration exceeds maximum value", new Throwable[0]);
            j2 = 18000000;
        }
        if (j2 < WorkRequest.MIN_BACKOFF_MILLIS) {
            Logger.get().warning(TAG, "Backoff delay duration less than minimum value", new Throwable[0]);
            j2 = 10000;
        }
        this.backoffDelayDuration = j2;
    }

    public void setPeriodic(long j2) {
        if (j2 < PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS) {
            Logger.get().warning(TAG, String.format("Interval duration lesser than minimum allowed value; Changed to %s", Long.valueOf(PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS)), new Throwable[0]);
            j2 = 900000;
        }
        setPeriodic(j2, j2);
    }

    @NonNull
    public String toString() {
        return C1499a.m582D(C1499a.m586H("{WorkSpec: "), this.f210id, "}");
    }

    public void setPeriodic(long j2, long j3) {
        if (j2 < PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS) {
            Logger.get().warning(TAG, String.format("Interval duration lesser than minimum allowed value; Changed to %s", Long.valueOf(PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS)), new Throwable[0]);
            j2 = 900000;
        }
        if (j3 < PeriodicWorkRequest.MIN_PERIODIC_FLEX_MILLIS) {
            Logger.get().warning(TAG, String.format("Flex duration lesser than minimum allowed value; Changed to %s", Long.valueOf(PeriodicWorkRequest.MIN_PERIODIC_FLEX_MILLIS)), new Throwable[0]);
            j3 = 300000;
        }
        if (j3 > j2) {
            Logger.get().warning(TAG, String.format("Flex duration greater than interval duration; Changed to %s", Long.valueOf(j2)), new Throwable[0]);
            j3 = j2;
        }
        this.intervalDuration = j2;
        this.flexDuration = j3;
    }

    public WorkSpec(@NonNull WorkSpec workSpec) {
        this.state = WorkInfo.State.ENQUEUED;
        Data data = Data.EMPTY;
        this.input = data;
        this.output = data;
        this.constraints = Constraints.NONE;
        this.backoffPolicy = BackoffPolicy.EXPONENTIAL;
        this.backoffDelayDuration = WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS;
        this.scheduleRequestedAt = -1L;
        this.f210id = workSpec.f210id;
        this.workerClassName = workSpec.workerClassName;
        this.state = workSpec.state;
        this.inputMergerClassName = workSpec.inputMergerClassName;
        this.input = new Data(workSpec.input);
        this.output = new Data(workSpec.output);
        this.initialDelay = workSpec.initialDelay;
        this.intervalDuration = workSpec.intervalDuration;
        this.flexDuration = workSpec.flexDuration;
        this.constraints = new Constraints(workSpec.constraints);
        this.runAttemptCount = workSpec.runAttemptCount;
        this.backoffPolicy = workSpec.backoffPolicy;
        this.backoffDelayDuration = workSpec.backoffDelayDuration;
        this.periodStartTime = workSpec.periodStartTime;
        this.minimumRetentionDuration = workSpec.minimumRetentionDuration;
        this.scheduleRequestedAt = workSpec.scheduleRequestedAt;
        this.runInForeground = workSpec.runInForeground;
    }
}
