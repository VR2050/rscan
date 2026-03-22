package androidx.camera.core.impl;

import android.view.Surface;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.impl.DeferrableSurface;
import androidx.camera.core.impl.utils.futures.FutureCallback;
import androidx.camera.core.impl.utils.futures.Futures;
import androidx.concurrent.futures.CallbackToFutureAdapter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public final class DeferrableSurfaces {
    private DeferrableSurfaces() {
    }

    public static void decrementAll(@NonNull List<DeferrableSurface> list) {
        Iterator<DeferrableSurface> it = list.iterator();
        while (it.hasNext()) {
            it.next().decrementUseCount();
        }
    }

    public static void incrementAll(@NonNull List<DeferrableSurface> list) {
        if (list.isEmpty()) {
            return;
        }
        int i2 = 0;
        do {
            try {
                list.get(i2).incrementUseCount();
                i2++;
            } catch (DeferrableSurface.SurfaceClosedException e2) {
                for (int i3 = i2 - 1; i3 >= 0; i3--) {
                    list.get(i3).decrementUseCount();
                }
                throw e2;
            }
        } while (i2 < list.size());
    }

    @NonNull
    public static InterfaceFutureC2413a<List<Surface>> surfaceListWithTimeout(@NonNull Collection<DeferrableSurface> collection, final boolean z, final long j2, @NonNull final Executor executor, @NonNull final ScheduledExecutorService scheduledExecutorService) {
        final ArrayList arrayList = new ArrayList();
        Iterator<DeferrableSurface> it = collection.iterator();
        while (it.hasNext()) {
            arrayList.add(it.next().getSurface());
        }
        return CallbackToFutureAdapter.getFuture(new CallbackToFutureAdapter.Resolver() { // from class: e.a.a.u1.i
            @Override // androidx.concurrent.futures.CallbackToFutureAdapter.Resolver
            public final Object attachCompleter(final CallbackToFutureAdapter.Completer completer) {
                List list = arrayList;
                ScheduledExecutorService scheduledExecutorService2 = scheduledExecutorService;
                final Executor executor2 = executor;
                final long j3 = j2;
                final boolean z2 = z;
                final InterfaceFutureC2413a successfulAsList = Futures.successfulAsList(list);
                final ScheduledFuture<?> schedule = scheduledExecutorService2.schedule(new Runnable() { // from class: e.a.a.u1.j
                    @Override // java.lang.Runnable
                    public final void run() {
                        Executor executor3 = executor2;
                        final InterfaceFutureC2413a interfaceFutureC2413a = successfulAsList;
                        final CallbackToFutureAdapter.Completer completer2 = completer;
                        final long j4 = j3;
                        executor3.execute(new Runnable() { // from class: e.a.a.u1.h
                            @Override // java.lang.Runnable
                            public final void run() {
                                InterfaceFutureC2413a interfaceFutureC2413a2 = InterfaceFutureC2413a.this;
                                CallbackToFutureAdapter.Completer completer3 = completer2;
                                long j5 = j4;
                                if (interfaceFutureC2413a2.isDone()) {
                                    return;
                                }
                                completer3.setException(new TimeoutException(C1499a.m630p("Cannot complete surfaceList within ", j5)));
                                interfaceFutureC2413a2.cancel(true);
                            }
                        });
                    }
                }, j3, TimeUnit.MILLISECONDS);
                completer.addCancellationListener(new Runnable() { // from class: e.a.a.u1.g
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceFutureC2413a.this.cancel(true);
                    }
                }, executor2);
                Futures.addCallback(successfulAsList, new FutureCallback<List<Surface>>() { // from class: androidx.camera.core.impl.DeferrableSurfaces.1
                    @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                    public void onFailure(Throwable th) {
                        completer.set(Collections.unmodifiableList(Collections.emptyList()));
                        schedule.cancel(true);
                    }

                    @Override // androidx.camera.core.impl.utils.futures.FutureCallback
                    public void onSuccess(@Nullable List<Surface> list2) {
                        ArrayList arrayList2 = new ArrayList(list2);
                        if (z2) {
                            arrayList2.removeAll(Collections.singleton(null));
                        }
                        completer.set(arrayList2);
                        schedule.cancel(true);
                    }
                }, executor2);
                return "surfaceList";
            }
        });
    }

    public static boolean tryIncrementAll(@NonNull List<DeferrableSurface> list) {
        try {
            incrementAll(list);
            return true;
        } catch (DeferrableSurface.SurfaceClosedException unused) {
            return false;
        }
    }
}
