package com.google.android.exoplayer2.scheduler;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.PersistableBundle;
import com.google.android.exoplayer2.util.Util;

/* JADX INFO: loaded from: classes2.dex */
public final class PlatformScheduler implements Scheduler {
    private static final String KEY_REQUIREMENTS = "requirements";
    private static final String KEY_SERVICE_ACTION = "service_action";
    private static final String KEY_SERVICE_PACKAGE = "service_package";
    private static final String TAG = "PlatformScheduler";
    private final int jobId;
    private final JobScheduler jobScheduler;
    private final ComponentName jobServiceComponentName;

    public PlatformScheduler(Context context, int jobId) {
        this.jobId = jobId;
        this.jobServiceComponentName = new ComponentName(context, (Class<?>) PlatformSchedulerService.class);
        this.jobScheduler = (JobScheduler) context.getSystemService("jobscheduler");
    }

    @Override // com.google.android.exoplayer2.scheduler.Scheduler
    public boolean schedule(Requirements requirements, String servicePackage, String serviceAction) {
        JobInfo jobInfo = buildJobInfo(this.jobId, this.jobServiceComponentName, requirements, serviceAction, servicePackage);
        int result = this.jobScheduler.schedule(jobInfo);
        logd("Scheduling job: " + this.jobId + " result: " + result);
        return result == 1;
    }

    @Override // com.google.android.exoplayer2.scheduler.Scheduler
    public boolean cancel() {
        logd("Canceling job: " + this.jobId);
        this.jobScheduler.cancel(this.jobId);
        return true;
    }

    private static JobInfo buildJobInfo(int jobId, ComponentName jobServiceComponentName, Requirements requirements, String serviceAction, String servicePackage) {
        int networkType;
        JobInfo.Builder builder = new JobInfo.Builder(jobId, jobServiceComponentName);
        int requiredNetworkType = requirements.getRequiredNetworkType();
        if (requiredNetworkType == 0) {
            networkType = 0;
        } else if (requiredNetworkType == 1) {
            networkType = 1;
        } else if (requiredNetworkType == 2) {
            networkType = 2;
        } else if (requiredNetworkType != 4) {
            if (requiredNetworkType == 8) {
                if (Util.SDK_INT >= 26) {
                    networkType = 4;
                } else {
                    throw new UnsupportedOperationException();
                }
            } else {
                throw new UnsupportedOperationException();
            }
        } else if (Util.SDK_INT >= 24) {
            networkType = 3;
        } else {
            throw new UnsupportedOperationException();
        }
        builder.setRequiredNetworkType(networkType);
        builder.setRequiresDeviceIdle(requirements.isIdleRequired());
        builder.setRequiresCharging(requirements.isChargingRequired());
        builder.setPersisted(true);
        PersistableBundle extras = new PersistableBundle();
        extras.putString(KEY_SERVICE_ACTION, serviceAction);
        extras.putString(KEY_SERVICE_PACKAGE, servicePackage);
        extras.putInt(KEY_REQUIREMENTS, requirements.getRequirements());
        builder.setExtras(extras);
        return builder.build();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void logd(String message) {
    }

    public static final class PlatformSchedulerService extends JobService {
        @Override // android.app.job.JobService
        public boolean onStartJob(JobParameters params) {
            PlatformScheduler.logd("PlatformSchedulerService started");
            PersistableBundle extras = params.getExtras();
            Requirements requirements = new Requirements(extras.getInt(PlatformScheduler.KEY_REQUIREMENTS));
            if (requirements.checkRequirements(this)) {
                PlatformScheduler.logd("Requirements are met");
                String serviceAction = extras.getString(PlatformScheduler.KEY_SERVICE_ACTION);
                String servicePackage = extras.getString(PlatformScheduler.KEY_SERVICE_PACKAGE);
                Intent intent = new Intent(serviceAction).setPackage(servicePackage);
                PlatformScheduler.logd("Starting service action: " + serviceAction + " package: " + servicePackage);
                Util.startForegroundService(this, intent);
                return false;
            }
            PlatformScheduler.logd("Requirements are not met");
            jobFinished(params, true);
            return false;
        }

        @Override // android.app.job.JobService
        public boolean onStopJob(JobParameters params) {
            return false;
        }
    }
}
