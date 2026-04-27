package im.uwrkaxlmjj.keepalive;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.content.Intent;
import im.uwrkaxlmjj.messenger.FileLog;

/* JADX INFO: loaded from: classes2.dex */
public class ScheduleService extends JobService {
    @Override // android.app.job.JobService
    public boolean onStartJob(JobParameters params) {
        FileLog.d("ScheduleService ---> onStartJob(): params = [" + params + "]");
        Intent intent = new Intent(getApplicationContext(), (Class<?>) DaemonService.class);
        startService(intent);
        jobFinished(params, false);
        return false;
    }

    @Override // android.app.job.JobService
    public boolean onStopJob(JobParameters params) {
        FileLog.d("ScheduleService ---> onStopJob(): params = [" + params + "]");
        return false;
    }
}
