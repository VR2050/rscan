package com.google.firebase.remoteconfig.internal;

import android.util.Log;
import com.google.android.gms.tasks.OnCanceledListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class ConfigCacheClient {
    static final long DISK_READ_TIMEOUT_IN_SECONDS = 5;
    private Task<ConfigContainer> cachedContainerTask = null;
    private final ExecutorService executorService;
    private final ConfigStorageClient storageClient;
    private static final Map<String, ConfigCacheClient> clientInstances = new HashMap();
    private static final Executor DIRECT_EXECUTOR = ConfigCacheClient$$Lambda$4.instance;

    private ConfigCacheClient(ExecutorService executorService, ConfigStorageClient storageClient) {
        this.executorService = executorService;
        this.storageClient = storageClient;
    }

    public Task<ConfigContainer> putWithoutWaitingForDiskWrite(ConfigContainer configContainer) {
        updateInMemoryConfigContainer(configContainer);
        return put(configContainer, false);
    }

    public ConfigContainer getBlocking() {
        return getBlocking(DISK_READ_TIMEOUT_IN_SECONDS);
    }

    ConfigContainer getBlocking(long diskReadTimeoutInSeconds) {
        synchronized (this) {
            if (this.cachedContainerTask != null && this.cachedContainerTask.isSuccessful()) {
                return this.cachedContainerTask.getResult();
            }
            try {
                return (ConfigContainer) await(get(), diskReadTimeoutInSeconds, TimeUnit.SECONDS);
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                Log.d(FirebaseRemoteConfig.TAG, "Reading from storage file failed.", e);
                return null;
            }
        }
    }

    public Task<ConfigContainer> put(ConfigContainer configContainer) {
        return put(configContainer, true);
    }

    public Task<ConfigContainer> put(ConfigContainer configContainer, boolean shouldUpdateInMemoryContainer) {
        return Tasks.call(this.executorService, ConfigCacheClient$$Lambda$1.lambdaFactory$(this, configContainer)).onSuccessTask(this.executorService, ConfigCacheClient$$Lambda$2.lambdaFactory$(this, shouldUpdateInMemoryContainer, configContainer));
    }

    static /* synthetic */ Task lambda$put$1(ConfigCacheClient configCacheClient, boolean shouldUpdateInMemoryContainer, ConfigContainer configContainer, Void unusedVoid) throws Exception {
        if (shouldUpdateInMemoryContainer) {
            configCacheClient.updateInMemoryConfigContainer(configContainer);
        }
        return Tasks.forResult(configContainer);
    }

    public synchronized Task<ConfigContainer> get() {
        if (this.cachedContainerTask == null || (this.cachedContainerTask.isComplete() && !this.cachedContainerTask.isSuccessful())) {
            ExecutorService executorService = this.executorService;
            ConfigStorageClient configStorageClient = this.storageClient;
            configStorageClient.getClass();
            this.cachedContainerTask = Tasks.call(executorService, ConfigCacheClient$$Lambda$3.lambdaFactory$(configStorageClient));
        }
        return this.cachedContainerTask;
    }

    public void clear() {
        synchronized (this) {
            this.cachedContainerTask = Tasks.forResult(null);
        }
        this.storageClient.clear();
    }

    private synchronized void updateInMemoryConfigContainer(ConfigContainer configContainer) {
        this.cachedContainerTask = Tasks.forResult(configContainer);
    }

    synchronized Task<ConfigContainer> getCachedContainerTask() {
        return this.cachedContainerTask;
    }

    public static synchronized ConfigCacheClient getInstance(ExecutorService executorService, ConfigStorageClient storageClient) {
        String fileName;
        fileName = storageClient.getFileName();
        if (!clientInstances.containsKey(fileName)) {
            clientInstances.put(fileName, new ConfigCacheClient(executorService, storageClient));
        }
        return clientInstances.get(fileName);
    }

    public static synchronized void clearInstancesForTest() {
        clientInstances.clear();
    }

    private static <TResult> TResult await(Task<TResult> task, long timeout, TimeUnit unit) throws ExecutionException, InterruptedException, TimeoutException {
        AwaitListener<TResult> waiter = new AwaitListener<>();
        task.addOnSuccessListener(DIRECT_EXECUTOR, waiter);
        task.addOnFailureListener(DIRECT_EXECUTOR, waiter);
        task.addOnCanceledListener(DIRECT_EXECUTOR, waiter);
        if (!waiter.await(timeout, unit)) {
            throw new TimeoutException("Task await timed out.");
        }
        if (task.isSuccessful()) {
            return task.getResult();
        }
        throw new ExecutionException(task.getException());
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    private static class AwaitListener<TResult> implements OnSuccessListener<TResult>, OnFailureListener, OnCanceledListener {
        private final CountDownLatch latch;

        private AwaitListener() {
            this.latch = new CountDownLatch(1);
        }

        @Override // com.google.android.gms.tasks.OnSuccessListener
        public void onSuccess(TResult o) {
            this.latch.countDown();
        }

        @Override // com.google.android.gms.tasks.OnFailureListener
        public void onFailure(Exception e) {
            this.latch.countDown();
        }

        @Override // com.google.android.gms.tasks.OnCanceledListener
        public void onCanceled() {
            this.latch.countDown();
        }

        public void await() throws InterruptedException {
            this.latch.await();
        }

        public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
            return this.latch.await(timeout, unit);
        }
    }
}
