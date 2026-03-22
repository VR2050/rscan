package com.google.android.exoplayer2.scheduler;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.content.Intent;
import android.os.PersistableBundle;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class PlatformScheduler$PlatformSchedulerService extends JobService {
    @Override // android.app.job.JobService
    public boolean onStartJob(JobParameters jobParameters) {
        PersistableBundle extras = jobParameters.getExtras();
        if (new Requirements(extras.getInt("requirements")).m4058b(this) == 0) {
            String string = extras.getString("service_action");
            String string2 = extras.getString("service_package");
            Objects.requireNonNull(string);
            Intent intent = new Intent(string).setPackage(string2);
            if (C2344d0.f6035a >= 26) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
        } else {
            jobFinished(jobParameters, true);
        }
        return false;
    }

    @Override // android.app.job.JobService
    public boolean onStopJob(JobParameters jobParameters) {
        return false;
    }
}
