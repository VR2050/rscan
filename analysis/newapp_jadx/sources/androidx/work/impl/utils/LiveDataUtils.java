package androidx.work.impl.utils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.arch.core.util.Function;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MediatorLiveData;
import androidx.lifecycle.Observer;
import androidx.work.impl.utils.taskexecutor.TaskExecutor;

@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public class LiveDataUtils {

    /* JADX INFO: Add missing generic type declarations: [In] */
    /* renamed from: androidx.work.impl.utils.LiveDataUtils$1 */
    public class C08181<In> implements Observer<In> {
        public Out mCurrentOutput = null;
        public final /* synthetic */ Object val$lock;
        public final /* synthetic */ Function val$mappingMethod;
        public final /* synthetic */ MediatorLiveData val$outputLiveData;
        public final /* synthetic */ TaskExecutor val$workTaskExecutor;

        public C08181(TaskExecutor taskExecutor, Object obj, Function function, MediatorLiveData mediatorLiveData) {
            this.val$workTaskExecutor = taskExecutor;
            this.val$lock = obj;
            this.val$mappingMethod = function;
            this.val$outputLiveData = mediatorLiveData;
        }

        @Override // androidx.lifecycle.Observer
        public void onChanged(@Nullable final In in) {
            this.val$workTaskExecutor.executeOnBackgroundThread(new Runnable() { // from class: androidx.work.impl.utils.LiveDataUtils.1.1
                /* JADX WARN: Multi-variable type inference failed */
                /* JADX WARN: Type inference failed for: r1v3, types: [Out, java.lang.Object] */
                @Override // java.lang.Runnable
                public void run() {
                    synchronized (C08181.this.val$lock) {
                        ?? apply = C08181.this.val$mappingMethod.apply(in);
                        C08181 c08181 = C08181.this;
                        Out out = c08181.mCurrentOutput;
                        if (out == 0 && apply != 0) {
                            c08181.mCurrentOutput = apply;
                            c08181.val$outputLiveData.postValue(apply);
                        } else if (out != 0 && !out.equals(apply)) {
                            C08181 c081812 = C08181.this;
                            c081812.mCurrentOutput = apply;
                            c081812.val$outputLiveData.postValue(apply);
                        }
                    }
                }
            });
        }
    }

    private LiveDataUtils() {
    }

    public static <In, Out> LiveData<Out> dedupedMappedLiveDataFor(@NonNull LiveData<In> liveData, @NonNull Function<In, Out> function, @NonNull TaskExecutor taskExecutor) {
        Object obj = new Object();
        MediatorLiveData mediatorLiveData = new MediatorLiveData();
        mediatorLiveData.addSource(liveData, new C08181(taskExecutor, obj, function, mediatorLiveData));
        return mediatorLiveData;
    }
}
