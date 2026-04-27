package com.facebook.react.animated;

import com.facebook.fbreact.specs.NativeAnimatedModuleSpec;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UIManagerListener;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.b;
import com.facebook.react.uimanager.C0436b0;
import com.facebook.react.uimanager.F0;
import com.facebook.react.uimanager.H0;
import com.facebook.react.uimanager.M;
import com.facebook.react.uimanager.UIManagerModule;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;
import q1.C0655b;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = NativeAnimatedModuleSpec.NAME)
public class NativeAnimatedModule extends NativeAnimatedModuleSpec implements LifecycleEventListener, UIManagerListener {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    public static final boolean ANIMATED_MODULE_DEBUG = false;
    private final M mAnimatedFrameCallback;
    private boolean mBatchingControlledByJS;
    private volatile long mCurrentBatchNumber;
    private volatile long mCurrentFrameNumber;
    private boolean mEnqueuedAnimationOnFrame;
    private boolean mInitializedForFabric;
    private boolean mInitializedForNonFabric;
    private final AtomicReference<com.facebook.react.animated.o> mNodesManager;
    private int mNumFabricAnimations;
    private int mNumNonFabricAnimations;
    private final A mOperations;
    private final A mPreOperations;
    private final com.facebook.react.modules.core.b mReactChoreographer;
    private int mUIManagerType;

    private class A {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Queue f6404a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private B f6405b;

        /* JADX WARN: Removed duplicated region for block: B:15:0x002c  */
        /* JADX WARN: Removed duplicated region for block: B:22:0x0036 A[EDGE_INSN: B:22:0x0036->B:18:0x0036 BREAK  A[LOOP:0: B:6:0x000d->B:19:0x0037], SYNTHETIC] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private java.util.List b(long r6) {
            /*
                r5 = this;
                boolean r0 = r5.d()
                r1 = 0
                if (r0 == 0) goto L8
                return r1
            L8:
                java.util.ArrayList r0 = new java.util.ArrayList
                r0.<init>()
            Ld:
                com.facebook.react.animated.NativeAnimatedModule$B r2 = r5.f6405b
                if (r2 == 0) goto L21
                long r2 = r2.b()
                int r2 = (r2 > r6 ? 1 : (r2 == r6 ? 0 : -1))
                if (r2 <= 0) goto L1a
                goto L36
            L1a:
                com.facebook.react.animated.NativeAnimatedModule$B r2 = r5.f6405b
                r0.add(r2)
                r5.f6405b = r1
            L21:
                java.util.Queue r2 = r5.f6404a
                java.lang.Object r2 = r2.poll()
                com.facebook.react.animated.NativeAnimatedModule$B r2 = (com.facebook.react.animated.NativeAnimatedModule.B) r2
                if (r2 != 0) goto L2c
                goto L36
            L2c:
                long r3 = r2.b()
                int r3 = (r3 > r6 ? 1 : (r3 == r6 ? 0 : -1))
                if (r3 <= 0) goto L37
                r5.f6405b = r2
            L36:
                return r0
            L37:
                r0.add(r2)
                goto Ld
            */
            throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.animated.NativeAnimatedModule.A.b(long):java.util.List");
        }

        void a(B b3) {
            this.f6404a.add(b3);
        }

        void c(long j3, com.facebook.react.animated.o oVar) {
            List listB = b(j3);
            if (listB != null) {
                Iterator it = listB.iterator();
                while (it.hasNext()) {
                    ((B) it.next()).a(oVar);
                }
            }
        }

        boolean d() {
            return this.f6404a.isEmpty() && this.f6405b == null;
        }

        private A() {
            this.f6404a = new ConcurrentLinkedQueue();
            this.f6405b = null;
        }
    }

    private abstract class B {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        long f6407a;

        abstract void a(com.facebook.react.animated.o oVar);

        public long b() {
            return this.f6407a;
        }

        public void c(long j3) {
            this.f6407a = j3;
        }

        private B() {
            this.f6407a = -1L;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.animated.NativeAnimatedModule$a, reason: case insensitive filesystem */
    class C0381a extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6409c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ double f6410d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        C0381a(int i3, double d3) {
            super();
            this.f6409c = i3;
            this.f6410d = d3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.w(this.f6409c, this.f6410d);
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.animated.NativeAnimatedModule$b, reason: case insensitive filesystem */
    class C0382b extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6412c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ double f6413d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        C0382b(int i3, double d3) {
            super();
            this.f6412c = i3;
            this.f6413d = d3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.v(this.f6412c, this.f6413d);
        }
    }

    class c extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6415c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        c(int i3) {
            super();
            this.f6415c = i3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.k(this.f6415c);
        }
    }

    class d extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6417c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        d(int i3) {
            super();
            this.f6417c = i3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.j(this.f6417c);
        }
    }

    class e extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6419c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f6420d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ ReadableMap f6421e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ Callback f6422f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        e(int i3, int i4, ReadableMap readableMap, Callback callback) {
            super();
            this.f6419c = i3;
            this.f6420d = i4;
            this.f6421e = readableMap;
            this.f6422f = callback;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.x(this.f6419c, this.f6420d, this.f6421e, this.f6422f);
        }
    }

    class f extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6424c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        f(int i3) {
            super();
            this.f6424c = i3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.z(this.f6424c);
        }
    }

    class g extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6426c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f6427d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        g(int i3, int i4) {
            super();
            this.f6426c = i3;
            this.f6427d = i4;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.e(this.f6426c, this.f6427d);
        }
    }

    class h extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6429c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f6430d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        h(int i3, int i4) {
            super();
            this.f6429c = i3;
            this.f6430d = i4;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.h(this.f6429c, this.f6430d);
        }
    }

    class i extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6432c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f6433d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        i(int i3, int i4) {
            super();
            this.f6432c = i3;
            this.f6433d = i4;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.d(this.f6432c, this.f6433d);
        }
    }

    class j extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6435c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f6436d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        j(int i3, int i4) {
            super();
            this.f6435c = i3;
            this.f6436d = i4;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.g(this.f6435c, this.f6436d);
        }
    }

    class k extends M {
        k(ReactContext reactContext) {
            super(reactContext);
        }

        @Override // com.facebook.react.uimanager.M
        protected void a(long j3) {
            try {
                NativeAnimatedModule.this.mEnqueuedAnimationOnFrame = false;
                com.facebook.react.animated.o nodesManager = NativeAnimatedModule.this.getNodesManager();
                if (nodesManager != null && nodesManager.p()) {
                    nodesManager.u(j3);
                }
                if (nodesManager != null && NativeAnimatedModule.this.mReactChoreographer != null) {
                    if (!C0655b.m() || nodesManager.p()) {
                        NativeAnimatedModule.this.enqueueFrameCallback();
                    }
                }
            } catch (Exception e3) {
                throw new RuntimeException(e3);
            }
        }
    }

    class l extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6439c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        l(int i3) {
            super();
            this.f6439c = i3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.t(this.f6439c);
        }
    }

    class m extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6441c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f6442d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ ReadableMap f6443e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        m(int i3, String str, ReadableMap readableMap) {
            super();
            this.f6441c = i3;
            this.f6442d = str;
            this.f6443e = readableMap;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.c(this.f6441c, this.f6442d, this.f6443e);
        }
    }

    class n extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6445c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f6446d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ int f6447e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        n(int i3, String str, int i4) {
            super();
            this.f6445c = i3;
            this.f6446d = str;
            this.f6447e = i4;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.s(this.f6445c, this.f6446d, this.f6447e);
        }
    }

    class o extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6449c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Callback f6450d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        o(int i3, Callback callback) {
            super();
            this.f6449c = i3;
            this.f6450d = callback;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.n(this.f6449c, this.f6450d);
        }
    }

    class p extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6452c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ ReadableArray f6453d;

        class a implements com.facebook.react.animated.c {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ int f6455a;

            a(int i3) {
                this.f6455a = i3;
            }

            @Override // com.facebook.react.animated.c
            public void a(double d3) {
                WritableMap writableMapCreateMap = Arguments.createMap();
                writableMapCreateMap.putInt("tag", this.f6455a);
                writableMapCreateMap.putDouble("value", d3);
                ReactApplicationContext reactApplicationContextIfActiveOrWarn = NativeAnimatedModule.this.getReactApplicationContextIfActiveOrWarn();
                if (reactApplicationContextIfActiveOrWarn != null) {
                    reactApplicationContextIfActiveOrWarn.emitDeviceEvent("onAnimatedValueUpdate", writableMapCreateMap);
                }
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        p(int i3, ReadableArray readableArray) {
            super();
            this.f6452c = i3;
            this.f6453d = readableArray;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            NativeAnimatedModule.this.getReactApplicationContextIfActiveOrWarn();
            int i3 = 0;
            while (i3 < this.f6452c) {
                int i4 = i3 + 1;
                switch (q.f6457a[z.b(this.f6453d.getInt(i3)).ordinal()]) {
                    case 1:
                        i3 += 2;
                        oVar.n(this.f6453d.getInt(i4), null);
                        break;
                    case 2:
                        i3 += 2;
                        int i5 = this.f6453d.getInt(i4);
                        oVar.y(i5, new a(i5));
                        break;
                    case 3:
                        i3 += 2;
                        oVar.B(this.f6453d.getInt(i4));
                        break;
                    case 4:
                        i3 += 2;
                        oVar.z(this.f6453d.getInt(i4));
                        break;
                    case 5:
                        i3 += 2;
                        oVar.k(this.f6453d.getInt(i4));
                        break;
                    case 6:
                        i3 += 2;
                        oVar.j(this.f6453d.getInt(i4));
                        break;
                    case 7:
                        i3 += 2;
                        oVar.t(this.f6453d.getInt(i4));
                        break;
                    case 8:
                        i3 += 2;
                        oVar.i(this.f6453d.getInt(i4));
                        break;
                    case 9:
                    case 10:
                        i3 += 2;
                        break;
                    case 11:
                        int i6 = i3 + 2;
                        i3 += 3;
                        oVar.f(this.f6453d.getInt(i4), this.f6453d.getMap(i6));
                        break;
                    case 12:
                        int i7 = i3 + 2;
                        i3 += 3;
                        oVar.C(this.f6453d.getInt(i4), this.f6453d.getMap(i7));
                        break;
                    case 13:
                        int i8 = i3 + 2;
                        i3 += 3;
                        oVar.e(this.f6453d.getInt(i4), this.f6453d.getInt(i8));
                        break;
                    case 14:
                        int i9 = i3 + 2;
                        i3 += 3;
                        oVar.h(this.f6453d.getInt(i4), this.f6453d.getInt(i9));
                        break;
                    case 15:
                        int i10 = i3 + 2;
                        i3 += 3;
                        oVar.w(this.f6453d.getInt(i4), this.f6453d.getDouble(i10));
                        break;
                    case 16:
                        int i11 = i3 + 2;
                        i3 += 3;
                        oVar.w(this.f6453d.getInt(i4), this.f6453d.getDouble(i11));
                        break;
                    case 17:
                        int i12 = i3 + 2;
                        int i13 = this.f6453d.getInt(i4);
                        i3 += 3;
                        int i14 = this.f6453d.getInt(i12);
                        NativeAnimatedModule.this.decrementInFlightAnimationsForViewTag(i14);
                        oVar.g(i13, i14);
                        break;
                    case 18:
                        if (C0655b.m()) {
                            NativeAnimatedModule.this.enqueueFrameCallback();
                        }
                        int i15 = this.f6453d.getInt(i4);
                        int i16 = i3 + 3;
                        int i17 = this.f6453d.getInt(i3 + 2);
                        i3 += 4;
                        oVar.x(i15, i17, this.f6453d.getMap(i16), null);
                        break;
                    case 19:
                        int i18 = this.f6453d.getInt(i4);
                        NativeAnimatedModule.this.decrementInFlightAnimationsForViewTag(i18);
                        int i19 = i3 + 3;
                        String string = this.f6453d.getString(i3 + 2);
                        i3 += 4;
                        oVar.s(i18, string, this.f6453d.getInt(i19));
                        break;
                    case 20:
                        int i20 = i3 + 2;
                        i3 += 3;
                        oVar.d(this.f6453d.getInt(i4), this.f6453d.getInt(i20));
                        break;
                    case 21:
                        int i21 = this.f6453d.getInt(i4);
                        int i22 = i3 + 3;
                        String string2 = this.f6453d.getString(i3 + 2);
                        i3 += 4;
                        oVar.c(i21, string2, this.f6453d.getMap(i22));
                        break;
                    default:
                        throw new IllegalArgumentException("Batch animation execution op: unknown op code");
                }
            }
        }
    }

    static /* synthetic */ class q {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f6457a;

        static {
            int[] iArr = new int[z.values().length];
            f6457a = iArr;
            try {
                iArr[z.OP_CODE_GET_VALUE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f6457a[z.OP_START_LISTENING_TO_ANIMATED_NODE_VALUE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f6457a[z.OP_STOP_LISTENING_TO_ANIMATED_NODE_VALUE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f6457a[z.OP_CODE_STOP_ANIMATION.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f6457a[z.OP_CODE_FLATTEN_ANIMATED_NODE_OFFSET.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f6457a[z.OP_CODE_EXTRACT_ANIMATED_NODE_OFFSET.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f6457a[z.OP_CODE_RESTORE_DEFAULT_VALUES.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                f6457a[z.OP_CODE_DROP_ANIMATED_NODE.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                f6457a[z.OP_CODE_ADD_LISTENER.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                f6457a[z.OP_CODE_REMOVE_LISTENERS.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                f6457a[z.OP_CODE_CREATE_ANIMATED_NODE.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                f6457a[z.OP_CODE_UPDATE_ANIMATED_NODE_CONFIG.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                f6457a[z.OP_CODE_CONNECT_ANIMATED_NODES.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                f6457a[z.OP_CODE_DISCONNECT_ANIMATED_NODES.ordinal()] = 14;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                f6457a[z.OP_CODE_SET_ANIMATED_NODE_VALUE.ordinal()] = 15;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                f6457a[z.OP_CODE_SET_ANIMATED_NODE_OFFSET.ordinal()] = 16;
            } catch (NoSuchFieldError unused16) {
            }
            try {
                f6457a[z.OP_CODE_DISCONNECT_ANIMATED_NODE_FROM_VIEW.ordinal()] = 17;
            } catch (NoSuchFieldError unused17) {
            }
            try {
                f6457a[z.OP_CODE_START_ANIMATING_NODE.ordinal()] = 18;
            } catch (NoSuchFieldError unused18) {
            }
            try {
                f6457a[z.OP_CODE_REMOVE_ANIMATED_EVENT_FROM_VIEW.ordinal()] = 19;
            } catch (NoSuchFieldError unused19) {
            }
            try {
                f6457a[z.OP_CODE_CONNECT_ANIMATED_NODE_TO_VIEW.ordinal()] = 20;
            } catch (NoSuchFieldError unused20) {
            }
            try {
                f6457a[z.OP_CODE_ADD_ANIMATED_EVENT_TO_VIEW.ordinal()] = 21;
            } catch (NoSuchFieldError unused21) {
            }
        }
    }

    class r implements F0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ long f6458a;

        r(long j3) {
            this.f6458a = j3;
        }

        @Override // com.facebook.react.uimanager.F0
        public void a(C0436b0 c0436b0) {
            NativeAnimatedModule.this.mPreOperations.c(this.f6458a, NativeAnimatedModule.this.getNodesManager());
        }
    }

    class s implements F0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ long f6460a;

        s(long j3) {
            this.f6460a = j3;
        }

        @Override // com.facebook.react.uimanager.F0
        public void a(C0436b0 c0436b0) {
            NativeAnimatedModule.this.mOperations.c(this.f6460a, NativeAnimatedModule.this.getNodesManager());
        }
    }

    class t extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6462c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ ReadableMap f6463d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        t(int i3, ReadableMap readableMap) {
            super();
            this.f6462c = i3;
            this.f6463d = readableMap;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.f(this.f6462c, this.f6463d);
        }
    }

    class u extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6465c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ ReadableMap f6466d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        u(int i3, ReadableMap readableMap) {
            super();
            this.f6465c = i3;
            this.f6466d = readableMap;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.C(this.f6465c, this.f6466d);
        }
    }

    class v implements com.facebook.react.animated.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f6468a;

        v(int i3) {
            this.f6468a = i3;
        }

        @Override // com.facebook.react.animated.c
        public void a(double d3) {
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("tag", this.f6468a);
            writableMapCreateMap.putDouble("value", d3);
            ReactApplicationContext reactApplicationContextIfActiveOrWarn = NativeAnimatedModule.this.getReactApplicationContextIfActiveOrWarn();
            if (reactApplicationContextIfActiveOrWarn != null) {
                reactApplicationContextIfActiveOrWarn.emitDeviceEvent("onAnimatedValueUpdate", writableMapCreateMap);
            }
        }
    }

    class w extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6470c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ com.facebook.react.animated.c f6471d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        w(int i3, com.facebook.react.animated.c cVar) {
            super();
            this.f6470c = i3;
            this.f6471d = cVar;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.y(this.f6470c, this.f6471d);
        }
    }

    class x extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6473c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        x(int i3) {
            super();
            this.f6473c = i3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.B(this.f6473c);
        }
    }

    class y extends B {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f6475c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        y(int i3) {
            super();
            this.f6475c = i3;
        }

        @Override // com.facebook.react.animated.NativeAnimatedModule.B
        public void a(com.facebook.react.animated.o oVar) {
            oVar.i(this.f6475c);
        }
    }

    private enum z {
        OP_CODE_CREATE_ANIMATED_NODE(1),
        OP_CODE_UPDATE_ANIMATED_NODE_CONFIG(2),
        OP_CODE_GET_VALUE(3),
        OP_START_LISTENING_TO_ANIMATED_NODE_VALUE(4),
        OP_STOP_LISTENING_TO_ANIMATED_NODE_VALUE(5),
        OP_CODE_CONNECT_ANIMATED_NODES(6),
        OP_CODE_DISCONNECT_ANIMATED_NODES(7),
        OP_CODE_START_ANIMATING_NODE(8),
        OP_CODE_STOP_ANIMATION(9),
        OP_CODE_SET_ANIMATED_NODE_VALUE(10),
        OP_CODE_SET_ANIMATED_NODE_OFFSET(11),
        OP_CODE_FLATTEN_ANIMATED_NODE_OFFSET(12),
        OP_CODE_EXTRACT_ANIMATED_NODE_OFFSET(13),
        OP_CODE_CONNECT_ANIMATED_NODE_TO_VIEW(14),
        OP_CODE_DISCONNECT_ANIMATED_NODE_FROM_VIEW(15),
        OP_CODE_RESTORE_DEFAULT_VALUES(16),
        OP_CODE_DROP_ANIMATED_NODE(17),
        OP_CODE_ADD_ANIMATED_EVENT_TO_VIEW(18),
        OP_CODE_REMOVE_ANIMATED_EVENT_FROM_VIEW(19),
        OP_CODE_ADD_LISTENER(20),
        OP_CODE_REMOVE_LISTENERS(21);


        /* JADX INFO: renamed from: x, reason: collision with root package name */
        private static z[] f6498x = null;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f6500b;

        z(int i3) {
            this.f6500b = i3;
        }

        public static z b(int i3) {
            if (f6498x == null) {
                f6498x = values();
            }
            return f6498x[i3 - 1];
        }
    }

    public NativeAnimatedModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
        this.mOperations = new A();
        this.mPreOperations = new A();
        this.mNodesManager = new AtomicReference<>();
        this.mBatchingControlledByJS = false;
        this.mInitializedForFabric = false;
        this.mInitializedForNonFabric = false;
        this.mEnqueuedAnimationOnFrame = false;
        this.mUIManagerType = 1;
        this.mNumFabricAnimations = 0;
        this.mNumNonFabricAnimations = 0;
        this.mReactChoreographer = com.facebook.react.modules.core.b.h();
        this.mAnimatedFrameCallback = new k(reactApplicationContext);
    }

    private void addOperation(B b3) {
        b3.c(this.mCurrentBatchNumber);
        this.mOperations.a(b3);
    }

    private void addPreOperation(B b3) {
        b3.c(this.mCurrentBatchNumber);
        this.mPreOperations.a(b3);
    }

    private void addUnbatchedOperation(B b3) {
        b3.c(-1L);
        this.mOperations.a(b3);
    }

    private void clearFrameCallback() {
        ((com.facebook.react.modules.core.b) Z0.a.c(this.mReactChoreographer)).n(b.a.f7051e, this.mAnimatedFrameCallback);
        this.mEnqueuedAnimationOnFrame = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void decrementInFlightAnimationsForViewTag(int i3) {
        if (L1.a.a(i3) == 2) {
            this.mNumFabricAnimations--;
        } else {
            this.mNumNonFabricAnimations--;
        }
        int i4 = this.mNumNonFabricAnimations;
        if (i4 == 0 && this.mNumFabricAnimations > 0 && this.mUIManagerType != 2) {
            this.mUIManagerType = 2;
        } else {
            if (this.mNumFabricAnimations != 0 || i4 <= 0 || this.mUIManagerType == 1) {
                return;
            }
            this.mUIManagerType = 1;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void enqueueFrameCallback() {
        if (this.mEnqueuedAnimationOnFrame) {
            return;
        }
        ((com.facebook.react.modules.core.b) Z0.a.c(this.mReactChoreographer)).k(b.a.f7051e, this.mAnimatedFrameCallback);
        this.mEnqueuedAnimationOnFrame = true;
    }

    private void initializeLifecycleEventListenersForViewTag(int i3) {
        UIManager uIManagerG;
        int iA = L1.a.a(i3);
        this.mUIManagerType = iA;
        if (iA == 2) {
            this.mNumFabricAnimations++;
        } else {
            this.mNumNonFabricAnimations++;
        }
        com.facebook.react.animated.o nodesManager = getNodesManager();
        if (nodesManager != null) {
            nodesManager.q(this.mUIManagerType);
        } else {
            ReactSoftExceptionLogger.logSoftException(NativeAnimatedModuleSpec.NAME, new RuntimeException("initializeLifecycleEventListenersForViewTag could not get NativeAnimatedNodesManager"));
        }
        if (this.mUIManagerType == 2) {
            if (this.mInitializedForFabric) {
                return;
            }
        } else if (this.mInitializedForNonFabric) {
            return;
        }
        ReactApplicationContext reactApplicationContext = getReactApplicationContext();
        if (reactApplicationContext == null || (uIManagerG = H0.g(reactApplicationContext, this.mUIManagerType)) == null) {
            return;
        }
        uIManagerG.addUIManagerEventListener(this);
        if (this.mUIManagerType == 2) {
            this.mInitializedForFabric = true;
        } else {
            this.mInitializedForNonFabric = true;
        }
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void addAnimatedEventToView(double d3, String str, ReadableMap readableMap) {
        int i3 = (int) d3;
        initializeLifecycleEventListenersForViewTag(i3);
        addOperation(new m(i3, str, readableMap));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void addListener(String str) {
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void connectAnimatedNodeToView(double d3, double d4) {
        int i3 = (int) d4;
        initializeLifecycleEventListenersForViewTag(i3);
        addOperation(new i((int) d3, i3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void connectAnimatedNodes(double d3, double d4) {
        addOperation(new g((int) d3, (int) d4));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void createAnimatedNode(double d3, ReadableMap readableMap) {
        addOperation(new t((int) d3, readableMap));
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void didDispatchMountItems(UIManager uIManager) {
        if (this.mUIManagerType != 2) {
            return;
        }
        long j3 = this.mCurrentBatchNumber - 1;
        if (!this.mBatchingControlledByJS) {
            this.mCurrentFrameNumber++;
            if (this.mCurrentFrameNumber - this.mCurrentBatchNumber > 2) {
                this.mCurrentBatchNumber = this.mCurrentFrameNumber;
                j3 = this.mCurrentBatchNumber;
            }
        }
        this.mPreOperations.c(j3, getNodesManager());
        this.mOperations.c(j3, getNodesManager());
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void didMountItems(UIManager uIManager) {
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void didScheduleMountItems(UIManager uIManager) {
        this.mCurrentFrameNumber++;
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void disconnectAnimatedNodeFromView(double d3, double d4) {
        int i3 = (int) d4;
        decrementInFlightAnimationsForViewTag(i3);
        addOperation(new j((int) d3, i3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void disconnectAnimatedNodes(double d3, double d4) {
        addOperation(new h((int) d3, (int) d4));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void dropAnimatedNode(double d3) {
        addOperation(new y((int) d3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void extractAnimatedNodeOffset(double d3) {
        addOperation(new d((int) d3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void finishOperationBatch() {
        this.mBatchingControlledByJS = false;
        this.mCurrentBatchNumber++;
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void flattenAnimatedNodeOffset(double d3) {
        addOperation(new c((int) d3));
    }

    public com.facebook.react.animated.o getNodesManager() {
        ReactApplicationContext reactApplicationContextIfActiveOrWarn;
        if (this.mNodesManager.get() == null && (reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn()) != null) {
            com.facebook.jni.a.a(this.mNodesManager, null, new com.facebook.react.animated.o(reactApplicationContextIfActiveOrWarn));
        }
        return this.mNodesManager.get();
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void getValue(double d3, Callback callback) {
        addOperation(new o((int) d3, callback));
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void initialize() {
        super.initialize();
        getReactApplicationContext().addLifecycleEventListener(this);
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void invalidate() {
        super.invalidate();
        getReactApplicationContext().removeLifecycleEventListener(this);
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostDestroy() {
        clearFrameCallback();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostPause() {
        clearFrameCallback();
    }

    @Override // com.facebook.react.bridge.LifecycleEventListener
    public void onHostResume() {
        enqueueFrameCallback();
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void queueAndExecuteBatchedOperations(ReadableArray readableArray) {
        int size = readableArray.size();
        int i3 = 0;
        while (i3 < size) {
            int i4 = i3 + 1;
            switch (q.f6457a[z.b(readableArray.getInt(i3)).ordinal()]) {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                case 10:
                    i3 += 2;
                    continue;
                case 11:
                case 12:
                case 13:
                case 14:
                case 15:
                case 16:
                case 17:
                    i3 += 3;
                    continue;
                case 18:
                case 19:
                    break;
                case 20:
                    int i5 = i3 + 2;
                    i3 += 3;
                    initializeLifecycleEventListenersForViewTag(readableArray.getInt(i5));
                    continue;
                case 21:
                    initializeLifecycleEventListenersForViewTag(readableArray.getInt(i4));
                    break;
                default:
                    throw new IllegalArgumentException("Batch animation execution op: fetching viewTag: unknown op code");
            }
            i3 += 4;
        }
        startOperationBatch();
        addUnbatchedOperation(new p(size, readableArray));
        finishOperationBatch();
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void removeAnimatedEventFromView(double d3, String str, double d4) {
        int i3 = (int) d3;
        decrementInFlightAnimationsForViewTag(i3);
        addOperation(new n(i3, str, (int) d4));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void removeListeners(double d3) {
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void restoreDefaultValues(double d3) {
        addPreOperation(new l((int) d3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void setAnimatedNodeOffset(double d3, double d4) {
        addOperation(new C0382b((int) d3, d4));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void setAnimatedNodeValue(double d3, double d4) {
        addOperation(new C0381a((int) d3, d4));
    }

    public void setNodesManager(com.facebook.react.animated.o oVar) {
        this.mNodesManager.set(oVar);
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void startAnimatingNode(double d3, double d4, ReadableMap readableMap, Callback callback) {
        addUnbatchedOperation(new e((int) d3, (int) d4, readableMap, callback));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void startListeningToAnimatedNodeValue(double d3) {
        int i3 = (int) d3;
        addOperation(new w(i3, new v(i3)));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void startOperationBatch() {
        this.mBatchingControlledByJS = true;
        this.mCurrentBatchNumber++;
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void stopAnimation(double d3) {
        addOperation(new f((int) d3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void stopListeningToAnimatedNodeValue(double d3) {
        addOperation(new x((int) d3));
    }

    @Override // com.facebook.fbreact.specs.NativeAnimatedModuleSpec
    public void updateAnimatedNodeConfig(double d3, ReadableMap readableMap) {
        addOperation(new u((int) d3, readableMap));
    }

    public void userDrivenScrollEnded(int i3) {
        com.facebook.react.animated.o oVar = this.mNodesManager.get();
        if (oVar == null) {
            return;
        }
        Set setM = oVar.m(i3, "topScrollEnded");
        if (setM.isEmpty()) {
            return;
        }
        WritableArray writableArrayCreateArray = Arguments.createArray();
        Iterator it = setM.iterator();
        while (it.hasNext()) {
            writableArrayCreateArray.pushInt(((Integer) it.next()).intValue());
        }
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putArray("tags", writableArrayCreateArray);
        ReactApplicationContext reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn();
        if (reactApplicationContextIfActiveOrWarn != null) {
            reactApplicationContextIfActiveOrWarn.emitDeviceEvent("onUserDrivenAnimationEnded", writableMapCreateMap);
        }
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void willDispatchViewUpdates(UIManager uIManager) {
        if ((this.mOperations.d() && this.mPreOperations.d()) || this.mUIManagerType == 2) {
            return;
        }
        long j3 = this.mCurrentBatchNumber;
        this.mCurrentBatchNumber = 1 + j3;
        r rVar = new r(j3);
        s sVar = new s(j3);
        UIManagerModule uIManagerModule = (UIManagerModule) uIManager;
        uIManagerModule.prependUIBlock(rVar);
        uIManagerModule.addUIBlock(sVar);
    }

    @Override // com.facebook.react.bridge.UIManagerListener
    public void willMountItems(UIManager uIManager) {
    }
}
