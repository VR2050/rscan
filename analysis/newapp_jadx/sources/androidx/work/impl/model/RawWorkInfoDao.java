package androidx.work.impl.model;

import androidx.annotation.NonNull;
import androidx.lifecycle.LiveData;
import androidx.room.Dao;
import androidx.room.RawQuery;
import androidx.sqlite.p004db.SupportSQLiteQuery;
import androidx.work.impl.model.WorkSpec;
import java.util.List;

@Dao
/* loaded from: classes.dex */
public interface RawWorkInfoDao {
    @NonNull
    @RawQuery
    List<WorkSpec.WorkInfoPojo> getWorkInfoPojos(@NonNull SupportSQLiteQuery supportSQLiteQuery);

    @NonNull
    @RawQuery
    LiveData<List<WorkSpec.WorkInfoPojo>> getWorkInfoPojosLiveData(@NonNull SupportSQLiteQuery supportSQLiteQuery);
}
