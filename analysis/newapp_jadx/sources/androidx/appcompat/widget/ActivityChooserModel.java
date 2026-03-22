package androidx.appcompat.widget;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.ResolveInfo;
import android.database.DataSetObservable;
import android.os.AsyncTask;
import android.text.TextUtils;
import android.util.Xml;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class ActivityChooserModel extends DataSetObservable {
    public static final String ATTRIBUTE_ACTIVITY = "activity";
    public static final String ATTRIBUTE_TIME = "time";
    public static final String ATTRIBUTE_WEIGHT = "weight";
    public static final boolean DEBUG = false;
    private static final int DEFAULT_ACTIVITY_INFLATION = 5;
    private static final float DEFAULT_HISTORICAL_RECORD_WEIGHT = 1.0f;
    public static final String DEFAULT_HISTORY_FILE_NAME = "activity_choser_model_history.xml";
    public static final int DEFAULT_HISTORY_MAX_LENGTH = 50;
    private static final String HISTORY_FILE_EXTENSION = ".xml";
    private static final int INVALID_INDEX = -1;
    public static final String TAG_HISTORICAL_RECORD = "historical-record";
    public static final String TAG_HISTORICAL_RECORDS = "historical-records";
    private OnChooseActivityListener mActivityChoserModelPolicy;
    public final Context mContext;
    public final String mHistoryFileName;
    private Intent mIntent;
    public static final String LOG_TAG = ActivityChooserModel.class.getSimpleName();
    private static final Object sRegistryLock = new Object();
    private static final Map<String, ActivityChooserModel> sDataModelRegistry = new HashMap();
    private final Object mInstanceLock = new Object();
    private final List<ActivityResolveInfo> mActivities = new ArrayList();
    private final List<HistoricalRecord> mHistoricalRecords = new ArrayList();
    private ActivitySorter mActivitySorter = new DefaultSorter();
    private int mHistoryMaxSize = 50;
    public boolean mCanReadHistoricalData = true;
    private boolean mReadShareHistoryCalled = false;
    private boolean mHistoricalRecordsChanged = true;
    private boolean mReloadActivities = false;

    public interface ActivityChooserModelClient {
        void setActivityChooserModel(ActivityChooserModel activityChooserModel);
    }

    public static final class ActivityResolveInfo implements Comparable<ActivityResolveInfo> {
        public final ResolveInfo resolveInfo;
        public float weight;

        public ActivityResolveInfo(ResolveInfo resolveInfo) {
            this.resolveInfo = resolveInfo;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return obj != null && ActivityResolveInfo.class == obj.getClass() && Float.floatToIntBits(this.weight) == Float.floatToIntBits(((ActivityResolveInfo) obj).weight);
        }

        public int hashCode() {
            return Float.floatToIntBits(this.weight) + 31;
        }

        public String toString() {
            StringBuilder m590L = C1499a.m590L("[", "resolveInfo:");
            m590L.append(this.resolveInfo.toString());
            m590L.append("; weight:");
            m590L.append(new BigDecimal(this.weight));
            m590L.append("]");
            return m590L.toString();
        }

        @Override // java.lang.Comparable
        public int compareTo(ActivityResolveInfo activityResolveInfo) {
            return Float.floatToIntBits(activityResolveInfo.weight) - Float.floatToIntBits(this.weight);
        }
    }

    public interface ActivitySorter {
        void sort(Intent intent, List<ActivityResolveInfo> list, List<HistoricalRecord> list2);
    }

    public static final class DefaultSorter implements ActivitySorter {
        private static final float WEIGHT_DECAY_COEFFICIENT = 0.95f;
        private final Map<ComponentName, ActivityResolveInfo> mPackageNameToActivityMap = new HashMap();

        @Override // androidx.appcompat.widget.ActivityChooserModel.ActivitySorter
        public void sort(Intent intent, List<ActivityResolveInfo> list, List<HistoricalRecord> list2) {
            Map<ComponentName, ActivityResolveInfo> map = this.mPackageNameToActivityMap;
            map.clear();
            int size = list.size();
            for (int i2 = 0; i2 < size; i2++) {
                ActivityResolveInfo activityResolveInfo = list.get(i2);
                activityResolveInfo.weight = 0.0f;
                ActivityInfo activityInfo = activityResolveInfo.resolveInfo.activityInfo;
                map.put(new ComponentName(activityInfo.packageName, activityInfo.name), activityResolveInfo);
            }
            float f2 = 1.0f;
            for (int size2 = list2.size() - 1; size2 >= 0; size2--) {
                HistoricalRecord historicalRecord = list2.get(size2);
                ActivityResolveInfo activityResolveInfo2 = map.get(historicalRecord.activity);
                if (activityResolveInfo2 != null) {
                    activityResolveInfo2.weight = (historicalRecord.weight * f2) + activityResolveInfo2.weight;
                    f2 *= WEIGHT_DECAY_COEFFICIENT;
                }
            }
            Collections.sort(list);
        }
    }

    public static final class HistoricalRecord {
        public final ComponentName activity;
        public final long time;
        public final float weight;

        public HistoricalRecord(String str, long j2, float f2) {
            this(ComponentName.unflattenFromString(str), j2, f2);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || HistoricalRecord.class != obj.getClass()) {
                return false;
            }
            HistoricalRecord historicalRecord = (HistoricalRecord) obj;
            ComponentName componentName = this.activity;
            if (componentName == null) {
                if (historicalRecord.activity != null) {
                    return false;
                }
            } else if (!componentName.equals(historicalRecord.activity)) {
                return false;
            }
            return this.time == historicalRecord.time && Float.floatToIntBits(this.weight) == Float.floatToIntBits(historicalRecord.weight);
        }

        public int hashCode() {
            ComponentName componentName = this.activity;
            int hashCode = componentName == null ? 0 : componentName.hashCode();
            long j2 = this.time;
            return Float.floatToIntBits(this.weight) + ((((hashCode + 31) * 31) + ((int) (j2 ^ (j2 >>> 32)))) * 31);
        }

        public String toString() {
            StringBuilder m590L = C1499a.m590L("[", "; activity:");
            m590L.append(this.activity);
            m590L.append("; time:");
            m590L.append(this.time);
            m590L.append("; weight:");
            m590L.append(new BigDecimal(this.weight));
            m590L.append("]");
            return m590L.toString();
        }

        public HistoricalRecord(ComponentName componentName, long j2, float f2) {
            this.activity = componentName;
            this.time = j2;
            this.weight = f2;
        }
    }

    public interface OnChooseActivityListener {
        boolean onChooseActivity(ActivityChooserModel activityChooserModel, Intent intent);
    }

    public final class PersistHistoryAsyncTask extends AsyncTask<Object, Void, Void> {
        public PersistHistoryAsyncTask() {
        }

        /* JADX WARN: Code restructure failed: missing block: B:12:0x0069, code lost:
        
            if (r14 != null) goto L36;
         */
        /* JADX WARN: Code restructure failed: missing block: B:16:0x006b, code lost:
        
            r14.close();
         */
        /* JADX WARN: Code restructure failed: missing block: B:30:0x007b, code lost:
        
            if (r14 == null) goto L27;
         */
        /* JADX WARN: Code restructure failed: missing block: B:33:0x0095, code lost:
        
            if (r14 == null) goto L27;
         */
        /* JADX WARN: Code restructure failed: missing block: B:36:0x0088, code lost:
        
            if (r14 == null) goto L27;
         */
        @Override // android.os.AsyncTask
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Void doInBackground(java.lang.Object... r14) {
            /*
                r13 = this;
                java.lang.String r0 = "historical-record"
                java.lang.String r1 = "historical-records"
                r2 = 0
                r3 = r14[r2]
                java.util.List r3 = (java.util.List) r3
                r4 = 1
                r14 = r14[r4]
                java.lang.String r14 = (java.lang.String) r14
                r5 = 0
                androidx.appcompat.widget.ActivityChooserModel r6 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch: java.io.FileNotFoundException -> La3
                android.content.Context r6 = r6.mContext     // Catch: java.io.FileNotFoundException -> La3
                java.io.FileOutputStream r14 = r6.openFileOutput(r14, r2)     // Catch: java.io.FileNotFoundException -> La3
                org.xmlpull.v1.XmlSerializer r6 = android.util.Xml.newSerializer()
                r6.setOutput(r14, r5)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r7 = "UTF-8"
                java.lang.Boolean r8 = java.lang.Boolean.TRUE     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.startDocument(r7, r8)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.startTag(r5, r1)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                int r7 = r3.size()     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r8 = 0
            L2d:
                if (r8 >= r7) goto L5f
                java.lang.Object r9 = r3.remove(r2)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                androidx.appcompat.widget.ActivityChooserModel$HistoricalRecord r9 = (androidx.appcompat.widget.ActivityChooserModel.HistoricalRecord) r9     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.startTag(r5, r0)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r10 = "activity"
                android.content.ComponentName r11 = r9.activity     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r11 = r11.flattenToString()     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.attribute(r5, r10, r11)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r10 = "time"
                long r11 = r9.time     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r11 = java.lang.String.valueOf(r11)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.attribute(r5, r10, r11)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r10 = "weight"
                float r9 = r9.weight     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                java.lang.String r9 = java.lang.String.valueOf(r9)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.attribute(r5, r10, r9)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.endTag(r5, r0)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                int r8 = r8 + 1
                goto L2d
            L5f:
                r6.endTag(r5, r1)     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                r6.endDocument()     // Catch: java.lang.Throwable -> L6f java.io.IOException -> L71 java.lang.IllegalStateException -> L7e java.lang.IllegalArgumentException -> L8b
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r4
                if (r14 == 0) goto L98
            L6b:
                r14.close()     // Catch: java.io.IOException -> L98
                goto L98
            L6f:
                r0 = move-exception
                goto L99
            L71:
                java.lang.String r0 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG     // Catch: java.lang.Throwable -> L6f
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch: java.lang.Throwable -> L6f
                java.lang.String r0 = r0.mHistoryFileName     // Catch: java.lang.Throwable -> L6f
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r4
                if (r14 == 0) goto L98
                goto L6b
            L7e:
                java.lang.String r0 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG     // Catch: java.lang.Throwable -> L6f
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch: java.lang.Throwable -> L6f
                java.lang.String r0 = r0.mHistoryFileName     // Catch: java.lang.Throwable -> L6f
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r4
                if (r14 == 0) goto L98
                goto L6b
            L8b:
                java.lang.String r0 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG     // Catch: java.lang.Throwable -> L6f
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch: java.lang.Throwable -> L6f
                java.lang.String r0 = r0.mHistoryFileName     // Catch: java.lang.Throwable -> L6f
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r4
                if (r14 == 0) goto L98
                goto L6b
            L98:
                return r5
            L99:
                androidx.appcompat.widget.ActivityChooserModel r1 = androidx.appcompat.widget.ActivityChooserModel.this
                r1.mCanReadHistoricalData = r4
                if (r14 == 0) goto La2
                r14.close()     // Catch: java.io.IOException -> La2
            La2:
                throw r0
            La3:
                java.lang.String r14 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG
                return r5
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActivityChooserModel.PersistHistoryAsyncTask.doInBackground(java.lang.Object[]):java.lang.Void");
        }
    }

    private ActivityChooserModel(Context context, String str) {
        this.mContext = context.getApplicationContext();
        if (TextUtils.isEmpty(str) || str.endsWith(HISTORY_FILE_EXTENSION)) {
            this.mHistoryFileName = str;
        } else {
            this.mHistoryFileName = C1499a.m637w(str, HISTORY_FILE_EXTENSION);
        }
    }

    private boolean addHistoricalRecord(HistoricalRecord historicalRecord) {
        boolean add = this.mHistoricalRecords.add(historicalRecord);
        if (add) {
            this.mHistoricalRecordsChanged = true;
            pruneExcessiveHistoricalRecordsIfNeeded();
            persistHistoricalDataIfNeeded();
            sortActivitiesIfNeeded();
            notifyChanged();
        }
        return add;
    }

    private void ensureConsistentState() {
        boolean loadActivitiesIfNeeded = loadActivitiesIfNeeded() | readHistoricalDataIfNeeded();
        pruneExcessiveHistoricalRecordsIfNeeded();
        if (loadActivitiesIfNeeded) {
            sortActivitiesIfNeeded();
            notifyChanged();
        }
    }

    public static ActivityChooserModel get(Context context, String str) {
        ActivityChooserModel activityChooserModel;
        synchronized (sRegistryLock) {
            Map<String, ActivityChooserModel> map = sDataModelRegistry;
            activityChooserModel = map.get(str);
            if (activityChooserModel == null) {
                activityChooserModel = new ActivityChooserModel(context, str);
                map.put(str, activityChooserModel);
            }
        }
        return activityChooserModel;
    }

    private boolean loadActivitiesIfNeeded() {
        if (!this.mReloadActivities || this.mIntent == null) {
            return false;
        }
        this.mReloadActivities = false;
        this.mActivities.clear();
        List<ResolveInfo> queryIntentActivities = this.mContext.getPackageManager().queryIntentActivities(this.mIntent, 0);
        int size = queryIntentActivities.size();
        for (int i2 = 0; i2 < size; i2++) {
            this.mActivities.add(new ActivityResolveInfo(queryIntentActivities.get(i2)));
        }
        return true;
    }

    private void persistHistoricalDataIfNeeded() {
        if (!this.mReadShareHistoryCalled) {
            throw new IllegalStateException("No preceding call to #readHistoricalData");
        }
        if (this.mHistoricalRecordsChanged) {
            this.mHistoricalRecordsChanged = false;
            if (TextUtils.isEmpty(this.mHistoryFileName)) {
                return;
            }
            new PersistHistoryAsyncTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new ArrayList(this.mHistoricalRecords), this.mHistoryFileName);
        }
    }

    private void pruneExcessiveHistoricalRecordsIfNeeded() {
        int size = this.mHistoricalRecords.size() - this.mHistoryMaxSize;
        if (size <= 0) {
            return;
        }
        this.mHistoricalRecordsChanged = true;
        for (int i2 = 0; i2 < size; i2++) {
            this.mHistoricalRecords.remove(0);
        }
    }

    private boolean readHistoricalDataIfNeeded() {
        if (!this.mCanReadHistoricalData || !this.mHistoricalRecordsChanged || TextUtils.isEmpty(this.mHistoryFileName)) {
            return false;
        }
        this.mCanReadHistoricalData = false;
        this.mReadShareHistoryCalled = true;
        readHistoricalDataImpl();
        return true;
    }

    private void readHistoricalDataImpl() {
        XmlPullParser newPullParser;
        try {
            FileInputStream openFileInput = this.mContext.openFileInput(this.mHistoryFileName);
            try {
                newPullParser = Xml.newPullParser();
                newPullParser.setInput(openFileInput, "UTF-8");
                for (int i2 = 0; i2 != 1 && i2 != 2; i2 = newPullParser.next()) {
                }
            } catch (IOException unused) {
                if (openFileInput == null) {
                    return;
                }
            } catch (XmlPullParserException unused2) {
                if (openFileInput == null) {
                    return;
                }
            } catch (Throwable th) {
                if (openFileInput != null) {
                    try {
                        openFileInput.close();
                    } catch (IOException unused3) {
                    }
                }
                throw th;
            }
            if (!TAG_HISTORICAL_RECORDS.equals(newPullParser.getName())) {
                throw new XmlPullParserException("Share records file does not start with historical-records tag.");
            }
            List<HistoricalRecord> list = this.mHistoricalRecords;
            list.clear();
            while (true) {
                int next = newPullParser.next();
                if (next == 1) {
                    if (openFileInput == null) {
                        return;
                    }
                } else if (next != 3 && next != 4) {
                    if (!TAG_HISTORICAL_RECORD.equals(newPullParser.getName())) {
                        throw new XmlPullParserException("Share records file not well-formed.");
                    }
                    list.add(new HistoricalRecord(newPullParser.getAttributeValue(null, ATTRIBUTE_ACTIVITY), Long.parseLong(newPullParser.getAttributeValue(null, "time")), Float.parseFloat(newPullParser.getAttributeValue(null, ATTRIBUTE_WEIGHT))));
                }
            }
            openFileInput.close();
        } catch (FileNotFoundException | IOException unused4) {
        }
    }

    private boolean sortActivitiesIfNeeded() {
        if (this.mActivitySorter == null || this.mIntent == null || this.mActivities.isEmpty() || this.mHistoricalRecords.isEmpty()) {
            return false;
        }
        this.mActivitySorter.sort(this.mIntent, this.mActivities, Collections.unmodifiableList(this.mHistoricalRecords));
        return true;
    }

    public Intent chooseActivity(int i2) {
        synchronized (this.mInstanceLock) {
            if (this.mIntent == null) {
                return null;
            }
            ensureConsistentState();
            ActivityInfo activityInfo = this.mActivities.get(i2).resolveInfo.activityInfo;
            ComponentName componentName = new ComponentName(activityInfo.packageName, activityInfo.name);
            Intent intent = new Intent(this.mIntent);
            intent.setComponent(componentName);
            if (this.mActivityChoserModelPolicy != null) {
                if (this.mActivityChoserModelPolicy.onChooseActivity(this, new Intent(intent))) {
                    return null;
                }
            }
            addHistoricalRecord(new HistoricalRecord(componentName, System.currentTimeMillis(), 1.0f));
            return intent;
        }
    }

    public ResolveInfo getActivity(int i2) {
        ResolveInfo resolveInfo;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            resolveInfo = this.mActivities.get(i2).resolveInfo;
        }
        return resolveInfo;
    }

    public int getActivityCount() {
        int size;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            size = this.mActivities.size();
        }
        return size;
    }

    public int getActivityIndex(ResolveInfo resolveInfo) {
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            List<ActivityResolveInfo> list = this.mActivities;
            int size = list.size();
            for (int i2 = 0; i2 < size; i2++) {
                if (list.get(i2).resolveInfo == resolveInfo) {
                    return i2;
                }
            }
            return -1;
        }
    }

    public ResolveInfo getDefaultActivity() {
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            if (this.mActivities.isEmpty()) {
                return null;
            }
            return this.mActivities.get(0).resolveInfo;
        }
    }

    public int getHistoryMaxSize() {
        int i2;
        synchronized (this.mInstanceLock) {
            i2 = this.mHistoryMaxSize;
        }
        return i2;
    }

    public int getHistorySize() {
        int size;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            size = this.mHistoricalRecords.size();
        }
        return size;
    }

    public Intent getIntent() {
        Intent intent;
        synchronized (this.mInstanceLock) {
            intent = this.mIntent;
        }
        return intent;
    }

    public void setActivitySorter(ActivitySorter activitySorter) {
        synchronized (this.mInstanceLock) {
            if (this.mActivitySorter == activitySorter) {
                return;
            }
            this.mActivitySorter = activitySorter;
            if (sortActivitiesIfNeeded()) {
                notifyChanged();
            }
        }
    }

    public void setDefaultActivity(int i2) {
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            ActivityResolveInfo activityResolveInfo = this.mActivities.get(i2);
            ActivityResolveInfo activityResolveInfo2 = this.mActivities.get(0);
            float f2 = activityResolveInfo2 != null ? (activityResolveInfo2.weight - activityResolveInfo.weight) + 5.0f : 1.0f;
            ActivityInfo activityInfo = activityResolveInfo.resolveInfo.activityInfo;
            addHistoricalRecord(new HistoricalRecord(new ComponentName(activityInfo.packageName, activityInfo.name), System.currentTimeMillis(), f2));
        }
    }

    public void setHistoryMaxSize(int i2) {
        synchronized (this.mInstanceLock) {
            if (this.mHistoryMaxSize == i2) {
                return;
            }
            this.mHistoryMaxSize = i2;
            pruneExcessiveHistoricalRecordsIfNeeded();
            if (sortActivitiesIfNeeded()) {
                notifyChanged();
            }
        }
    }

    public void setIntent(Intent intent) {
        synchronized (this.mInstanceLock) {
            if (this.mIntent == intent) {
                return;
            }
            this.mIntent = intent;
            this.mReloadActivities = true;
            ensureConsistentState();
        }
    }

    public void setOnChooseActivityListener(OnChooseActivityListener onChooseActivityListener) {
        synchronized (this.mInstanceLock) {
            this.mActivityChoserModelPolicy = onChooseActivityListener;
        }
    }
}
