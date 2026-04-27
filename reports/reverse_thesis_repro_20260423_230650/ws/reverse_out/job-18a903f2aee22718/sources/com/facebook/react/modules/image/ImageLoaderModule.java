package com.facebook.react.modules.image;

import D1.b;
import I0.C0194t;
import android.net.Uri;
import android.os.AsyncTask;
import android.util.SparseArray;
import b0.AbstractC0311a;
import com.facebook.fbreact.specs.NativeImageLoaderAndroidSpec;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.BaseJavaModule;
import com.facebook.react.bridge.GuardedAsyncTask;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.views.image.f;
import h0.AbstractC0546b;
import h0.InterfaceC0547c;
import h2.r;
import kotlin.jvm.internal.DefaultConstructorMarker;
import l0.AbstractC0616d;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "ImageLoader")
public final class ImageLoaderModule extends NativeImageLoaderAndroidSpec implements LifecycleEventListener {
    public static final a Companion = new a(null);
    private static final String ERROR_GET_SIZE_FAILURE = "E_GET_SIZE_FAILURE";
    private static final String ERROR_INVALID_URI = "E_INVALID_URI";
    private static final String ERROR_PREFETCH_FAILURE = "E_PREFETCH_FAILURE";
    public static final String NAME = "ImageLoader";
    private C0194t _imagePipeline;
    private final Object callerContext;
    private f callerContextFactory;
    private final Object enqueuedRequestMonitor;
    private final SparseArray<InterfaceC0547c> enqueuedRequests;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public static final class b extends AbstractC0546b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Promise f7105a;

        b(Promise promise) {
            this.f7105a = promise;
        }

        @Override // h0.AbstractC0546b
        protected void e(InterfaceC0547c interfaceC0547c) {
            j.f(interfaceC0547c, "dataSource");
            this.f7105a.reject(ImageLoaderModule.ERROR_GET_SIZE_FAILURE, interfaceC0547c.f());
        }

        @Override // h0.AbstractC0546b
        protected void f(InterfaceC0547c interfaceC0547c) {
            j.f(interfaceC0547c, "dataSource");
            if (interfaceC0547c.e()) {
                AbstractC0311a abstractC0311a = (AbstractC0311a) interfaceC0547c.a();
                try {
                    if (abstractC0311a == null) {
                        this.f7105a.reject(ImageLoaderModule.ERROR_GET_SIZE_FAILURE, "Failed to get the size of the image");
                        return;
                    }
                    try {
                        Object objP = abstractC0311a.P();
                        j.e(objP, "get(...)");
                        N0.d dVar = (N0.d) objP;
                        WritableMap writableMapCreateMap = Arguments.createMap();
                        j.e(writableMapCreateMap, "createMap(...)");
                        writableMapCreateMap.putInt("width", dVar.h());
                        writableMapCreateMap.putInt("height", dVar.d());
                        this.f7105a.resolve(writableMapCreateMap);
                    } catch (Exception e3) {
                        this.f7105a.reject(ImageLoaderModule.ERROR_GET_SIZE_FAILURE, e3);
                    }
                } finally {
                    AbstractC0311a.D(abstractC0311a);
                }
            }
        }
    }

    public static final class c extends AbstractC0546b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Promise f7106a;

        c(Promise promise) {
            this.f7106a = promise;
        }

        @Override // h0.AbstractC0546b
        protected void e(InterfaceC0547c interfaceC0547c) {
            j.f(interfaceC0547c, "dataSource");
            this.f7106a.reject(ImageLoaderModule.ERROR_GET_SIZE_FAILURE, interfaceC0547c.f());
        }

        @Override // h0.AbstractC0546b
        protected void f(InterfaceC0547c interfaceC0547c) {
            j.f(interfaceC0547c, "dataSource");
            if (interfaceC0547c.e()) {
                AbstractC0311a abstractC0311a = (AbstractC0311a) interfaceC0547c.a();
                try {
                    if (abstractC0311a == null) {
                        this.f7106a.reject(ImageLoaderModule.ERROR_GET_SIZE_FAILURE, "Failed to get the size of the image");
                        return;
                    }
                    try {
                        Object objP = abstractC0311a.P();
                        j.e(objP, "get(...)");
                        N0.d dVar = (N0.d) objP;
                        WritableMap writableMapCreateMap = Arguments.createMap();
                        j.e(writableMapCreateMap, "createMap(...)");
                        writableMapCreateMap.putInt("width", dVar.h());
                        writableMapCreateMap.putInt("height", dVar.d());
                        this.f7106a.resolve(writableMapCreateMap);
                    } catch (Exception e3) {
                        this.f7106a.reject(ImageLoaderModule.ERROR_GET_SIZE_FAILURE, e3);
                    }
                } finally {
                    AbstractC0311a.D(abstractC0311a);
                }
            }
        }
    }

    public static final class d extends AbstractC0546b {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f7108b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Promise f7109c;

        d(int i3, Promise promise) {
            this.f7108b = i3;
            this.f7109c = promise;
        }

        @Override // h0.AbstractC0546b
        protected void e(InterfaceC0547c interfaceC0547c) {
            j.f(interfaceC0547c, "dataSource");
            try {
                ImageLoaderModule.this.removeRequest(this.f7108b);
                this.f7109c.reject(ImageLoaderModule.ERROR_PREFETCH_FAILURE, interfaceC0547c.f());
            } finally {
                interfaceC0547c.close();
            }
        }

        @Override // h0.AbstractC0546b
        protected void f(InterfaceC0547c interfaceC0547c) {
            j.f(interfaceC0547c, "dataSource");
            if (interfaceC0547c.e()) {
                try {
                    try {
                        ImageLoaderModule.this.removeRequest(this.f7108b);
                        this.f7109c.resolve(Boolean.TRUE);
                    } catch (Exception e3) {
                        this.f7109c.reject(ImageLoaderModule.ERROR_PREFETCH_FAILURE, e3);
                    }
                } finally {
                    interfaceC0547c.close();
                }
            }
        }
    }

    public static final class e extends GuardedAsyncTask {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ReadableArray f7111b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Promise f7112c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        e(ReadableArray readableArray, Promise promise, ReactApplicationContext reactApplicationContext) {
            super(reactApplicationContext);
            this.f7111b = readableArray;
            this.f7112c = promise;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.react.bridge.GuardedAsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public void doInBackgroundGuarded(Void... voidArr) {
            j.f(voidArr, "params");
            WritableMap writableMapCreateMap = Arguments.createMap();
            j.e(writableMapCreateMap, "createMap(...)");
            C0194t imagePipeline = ImageLoaderModule.this.getImagePipeline();
            int size = this.f7111b.size();
            for (int i3 = 0; i3 < size; i3++) {
                String string = this.f7111b.getString(i3);
                if (string != null && string.length() != 0) {
                    Uri uri = Uri.parse(string);
                    if (imagePipeline.r(uri)) {
                        writableMapCreateMap.putString(string, "memory");
                    } else if (imagePipeline.t(uri)) {
                        writableMapCreateMap.putString(string, "disk");
                    }
                }
            }
            this.f7112c.resolve(writableMapCreateMap);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ImageLoaderModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
        j.f(reactApplicationContext, "reactContext");
        this.enqueuedRequestMonitor = new Object();
        this.enqueuedRequests = new SparseArray<>();
        this.callerContext = this;
    }

    private final Object getCallerContext() {
        return this.callerContext;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final C0194t getImagePipeline() {
        C0194t c0194t = this._imagePipeline;
        if (c0194t != null) {
            return c0194t;
        }
        C0194t c0194tA = AbstractC0616d.a();
        j.e(c0194tA, "getImagePipeline(...)");
        return c0194tA;
    }

    private final void registerRequest(int i3, InterfaceC0547c interfaceC0547c) {
        synchronized (this.enqueuedRequestMonitor) {
            this.enqueuedRequests.put(i3, interfaceC0547c);
            r rVar = r.f9288a;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final InterfaceC0547c removeRequest(int i3) {
        InterfaceC0547c interfaceC0547c;
        synchronized (this.enqueuedRequestMonitor) {
            interfaceC0547c = this.enqueuedRequests.get(i3);
            this.enqueuedRequests.remove(i3);
        }
        return interfaceC0547c;
    }

    private final void setImagePipeline(C0194t c0194t) {
        this._imagePipeline = c0194t;
    }

    @Override // com.facebook.fbreact.specs.NativeImageLoaderAndroidSpec
    public void abortRequest(double d3) {
        InterfaceC0547c interfaceC0547cRemoveRequest = removeRequest((int) d3);
        if (interfaceC0547cRemoveRequest != null) {
            interfaceC0547cRemoveRequest.close();
        }
    }

    @Override // com.facebook.fbreact.specs.NativeImageLoaderAndroidSpec
    @ReactMethod
    public void getSize(String str, Promise promise) {
        j.f(promise, BaseJavaModule.METHOD_TYPE_PROMISE);
        if (str == null || str.length() == 0) {
            promise.reject(ERROR_INVALID_URI, "Cannot get the size of an image for an empty URI");
            return;
        }
        ReactApplicationContext reactApplicationContext = getReactApplicationContext();
        j.e(reactApplicationContext, "getReactApplicationContext(...)");
        T0.b bVarA = T0.c.x(new W1.a(reactApplicationContext, str, 0.0d, 0.0d, null, 28, null).f()).a();
        j.e(bVarA, "build(...)");
        getImagePipeline().k(bVarA, getCallerContext()).h(new b(promise), V.a.b());
    }

    @Override // com.facebook.fbreact.specs.NativeImageLoaderAndroidSpec
    @ReactMethod
    public void getSizeWithHeaders(String str, ReadableMap readableMap, Promise promise) {
        j.f(promise, BaseJavaModule.METHOD_TYPE_PROMISE);
        if (str == null || str.length() == 0) {
            promise.reject(ERROR_INVALID_URI, "Cannot get the size of an image for an empty URI");
            return;
        }
        ReactApplicationContext reactApplicationContext = getReactApplicationContext();
        j.e(reactApplicationContext, "getReactApplicationContext(...)");
        T0.c cVarX = T0.c.x(new W1.a(reactApplicationContext, str, 0.0d, 0.0d, null, 28, null).f());
        j.e(cVarX, "newBuilderWithSource(...)");
        getImagePipeline().k(b.a.c(D1.b.f599D, cVarX, readableMap, null, 4, null), getCallerContext()).h(new c(promise), V.a.b());
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        synchronized (this.enqueuedRequestMonitor) {
            try {
                int size = this.enqueuedRequests.size();
                for (int i3 = 0; i3 < size; i3++) {
                    InterfaceC0547c interfaceC0547cValueAt = this.enqueuedRequests.valueAt(i3);
                    j.e(interfaceC0547cValueAt, "valueAt(...)");
                    interfaceC0547cValueAt.close();
                }
                this.enqueuedRequests.clear();
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
    }

    @Override // com.facebook.fbreact.specs.NativeImageLoaderAndroidSpec
    public void prefetchImage(String str, double d3, Promise promise) {
        j.f(promise, BaseJavaModule.METHOD_TYPE_PROMISE);
        int i3 = (int) d3;
        if (str == null || str.length() == 0) {
            promise.reject(ERROR_INVALID_URI, "Cannot prefetch an image for an empty URI");
            return;
        }
        T0.b bVarA = T0.c.x(Uri.parse(str)).a();
        j.e(bVarA, "build(...)");
        InterfaceC0547c interfaceC0547cY = getImagePipeline().y(bVarA, getCallerContext());
        d dVar = new d(i3, promise);
        registerRequest(i3, interfaceC0547cY);
        interfaceC0547cY.h(dVar, V.a.b());
    }

    @Override // com.facebook.fbreact.specs.NativeImageLoaderAndroidSpec
    @ReactMethod
    public void queryCache(ReadableArray readableArray, Promise promise) {
        j.f(readableArray, "uris");
        j.f(promise, BaseJavaModule.METHOD_TYPE_PROMISE);
        new e(readableArray, promise, getReactApplicationContext()).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ImageLoaderModule(ReactApplicationContext reactApplicationContext, Object obj) {
        super(reactApplicationContext);
        j.f(reactApplicationContext, "reactContext");
        this.enqueuedRequestMonitor = new Object();
        this.enqueuedRequests = new SparseArray<>();
        this.callerContext = obj;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ImageLoaderModule(ReactApplicationContext reactApplicationContext, C0194t c0194t, f fVar) {
        super(reactApplicationContext);
        j.f(reactApplicationContext, "reactContext");
        j.f(c0194t, "imagePipeline");
        j.f(fVar, "callerContextFactory");
        this.enqueuedRequestMonitor = new Object();
        this.enqueuedRequests = new SparseArray<>();
        setImagePipeline(c0194t);
        this.callerContext = null;
    }
}
