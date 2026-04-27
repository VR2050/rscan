package com.facebook.react.animated;

import O1.d;
import android.util.SparseArray;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.JSApplicationCausedNativeException;
import com.facebook.react.bridge.JSApplicationIllegalArgumentException;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.H0;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public class o implements O1.g {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ReactApplicationContext f6568e;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final SparseArray f6564a = new SparseArray();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final SparseArray f6565b = new SparseArray();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final SparseArray f6566c = new SparseArray();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f6567d = new ArrayList();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f6569f = 0;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final List f6570g = new LinkedList();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f6571h = false;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f6572i = false;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f6573j = false;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ O1.d f6574b;

        a(O1.d dVar) {
            this.f6574b = dVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            o.this.o(this.f6574b);
        }
    }

    public o(ReactApplicationContext reactApplicationContext) {
        this.f6568e = reactApplicationContext;
    }

    private void A(b bVar) {
        WritableArray writableArrayCreateArray = null;
        int i3 = 0;
        while (i3 < this.f6565b.size()) {
            e eVar = (e) this.f6565b.valueAt(i3);
            if (bVar.equals(eVar.f6509b)) {
                if (eVar.f6510c != null) {
                    WritableMap writableMapCreateMap = Arguments.createMap();
                    writableMapCreateMap.putBoolean("finished", false);
                    writableMapCreateMap.putDouble("value", eVar.f6509b.f6621f);
                    eVar.f6510c.invoke(writableMapCreateMap);
                } else if (this.f6568e != null) {
                    WritableMap writableMapCreateMap2 = Arguments.createMap();
                    writableMapCreateMap2.putInt("animationId", eVar.f6511d);
                    writableMapCreateMap2.putBoolean("finished", false);
                    writableMapCreateMap2.putDouble("value", eVar.f6509b.f6621f);
                    if (writableArrayCreateArray == null) {
                        writableArrayCreateArray = Arguments.createArray();
                    }
                    writableArrayCreateArray.pushMap(writableMapCreateMap2);
                }
                this.f6565b.removeAt(i3);
                i3--;
            }
            i3++;
        }
        if (writableArrayCreateArray != null) {
            this.f6568e.emitDeviceEvent("onNativeAnimatedModuleAnimationFinished", writableArrayCreateArray);
        }
    }

    private void D(List list) {
        int i3 = this.f6569f;
        int i4 = i3 + 1;
        this.f6569f = i4;
        if (i4 == 0) {
            this.f6569f = i3 + 2;
        }
        ArrayDeque arrayDeque = new ArrayDeque();
        Iterator it = list.iterator();
        int i5 = 0;
        while (it.hasNext()) {
            b bVar = (b) it.next();
            int i6 = bVar.f6506c;
            int i7 = this.f6569f;
            if (i6 != i7) {
                bVar.f6506c = i7;
                i5++;
                arrayDeque.add(bVar);
            }
        }
        while (!arrayDeque.isEmpty()) {
            b bVar2 = (b) arrayDeque.poll();
            if (bVar2.f6504a != null) {
                for (int i8 = 0; i8 < bVar2.f6504a.size(); i8++) {
                    b bVar3 = (b) bVar2.f6504a.get(i8);
                    bVar3.f6505b++;
                    int i9 = bVar3.f6506c;
                    int i10 = this.f6569f;
                    if (i9 != i10) {
                        bVar3.f6506c = i10;
                        i5++;
                        arrayDeque.add(bVar3);
                    }
                }
            }
        }
        int i11 = this.f6569f;
        int i12 = i11 + 1;
        this.f6569f = i12;
        if (i12 == 0) {
            this.f6569f = i11 + 2;
        }
        Iterator it2 = list.iterator();
        int i13 = 0;
        while (it2.hasNext()) {
            b bVar4 = (b) it2.next();
            if (bVar4.f6505b == 0) {
                int i14 = bVar4.f6506c;
                int i15 = this.f6569f;
                if (i14 != i15) {
                    bVar4.f6506c = i15;
                    i13++;
                    arrayDeque.add(bVar4);
                }
            }
        }
        int i16 = 0;
        while (!arrayDeque.isEmpty()) {
            b bVar5 = (b) arrayDeque.poll();
            try {
                bVar5.h();
                if (bVar5 instanceof q) {
                    ((q) bVar5).m();
                }
            } catch (JSApplicationCausedNativeException e3) {
                Y.a.n("NativeAnimatedNodesManager", "Native animation workaround, frame lost as result of race condition", e3);
            }
            if (bVar5 instanceof w) {
                ((w) bVar5).m();
            }
            if (bVar5.f6504a != null) {
                for (int i17 = 0; i17 < bVar5.f6504a.size(); i17++) {
                    b bVar6 = (b) bVar5.f6504a.get(i17);
                    int i18 = bVar6.f6505b - 1;
                    bVar6.f6505b = i18;
                    int i19 = bVar6.f6506c;
                    int i20 = this.f6569f;
                    if (i19 != i20 && i18 == 0) {
                        bVar6.f6506c = i20;
                        i13++;
                        arrayDeque.add(bVar6);
                    } else if (i19 == i20) {
                        i16++;
                    }
                }
            }
        }
        if (i5 == i13) {
            this.f6573j = false;
            return;
        }
        if (this.f6573j) {
            return;
        }
        this.f6573j = true;
        Y.a.m("NativeAnimatedNodesManager", "Detected animation cycle or disconnected graph. ");
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            Y.a.m("NativeAnimatedNodesManager", ((b) it3.next()).f());
        }
        IllegalStateException illegalStateException = new IllegalStateException("Looks like animated nodes graph has " + (i16 > 0 ? "cycles (" + i16 + ")" : "disconnected regions") + ", there are " + i5 + " but toposort visited only " + i13);
        boolean z3 = this.f6571h;
        if (z3 && i16 == 0) {
            ReactSoftExceptionLogger.logSoftException("NativeAnimatedNodesManager", new ReactNoCrashSoftException(illegalStateException));
        } else {
            if (!z3) {
                throw illegalStateException;
            }
            ReactSoftExceptionLogger.logSoftException("NativeAnimatedNodesManager", new ReactNoCrashSoftException(illegalStateException));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void o(O1.d dVar) {
        if (this.f6567d.isEmpty()) {
            return;
        }
        d.b bVarH = dVar.h();
        boolean z3 = false;
        for (EventAnimationDriver eventAnimationDriver : this.f6567d) {
            if (bVarH.a(eventAnimationDriver.viewTag, eventAnimationDriver.eventName)) {
                A(eventAnimationDriver.valueNode);
                dVar.d(eventAnimationDriver);
                this.f6570g.add(eventAnimationDriver.valueNode);
                z3 = true;
            }
        }
        if (z3) {
            D(this.f6570g);
            this.f6570g.clear();
        }
    }

    private String r(String str) {
        if (!str.startsWith("on")) {
            return str;
        }
        return "top" + str.substring(2);
    }

    public void B(int i3) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar != null && (bVar instanceof w)) {
            ((w) bVar).n(null);
            return;
        }
        throw new JSApplicationIllegalArgumentException("startListeningToAnimatedNodeValue: Animated node [" + i3 + "] does not exist, or is not a 'value' node");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void C(int i3, ReadableMap readableMap) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == 0) {
            throw new JSApplicationIllegalArgumentException("updateAnimatedNode: Animated node [" + i3 + "] does not exist");
        }
        if (bVar instanceof d) {
            A(bVar);
            ((d) bVar).a(readableMap);
            this.f6566c.put(i3, bVar);
        }
    }

    @Override // O1.g
    public void a(O1.d dVar) {
        if (UiThreadUtil.isOnUiThread()) {
            o(dVar);
        } else {
            UiThreadUtil.runOnUiThread(new a(dVar));
        }
    }

    public void c(int i3, String str, ReadableMap readableMap) {
        int i4 = readableMap.getInt("animatedValueTag");
        b bVar = (b) this.f6564a.get(i4);
        if (bVar == null) {
            throw new JSApplicationIllegalArgumentException("addAnimatedEventToView: Animated node with tag [" + i4 + "] does not exist");
        }
        if (!(bVar instanceof w)) {
            throw new JSApplicationIllegalArgumentException("addAnimatedEventToView: Animated node on view [" + i3 + "] connected to event handler (" + str + ") should be of type " + w.class.getName());
        }
        ReadableArray array = readableMap.getArray("nativeEventPath");
        ArrayList arrayList = new ArrayList(array.size());
        for (int i5 = 0; i5 < array.size(); i5++) {
            arrayList.add(array.getString(i5));
        }
        String strR = r(str);
        this.f6567d.add(new EventAnimationDriver(strR, i3, arrayList, (w) bVar));
        if (strR.equals("topScroll")) {
            c(i3, "topScrollEnded", readableMap);
        }
    }

    public void d(int i3, int i4) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == null) {
            throw new JSApplicationIllegalArgumentException("connectAnimatedNodeToView: Animated node with tag [" + i3 + "] does not exist");
        }
        if (!(bVar instanceof q)) {
            throw new JSApplicationIllegalArgumentException("connectAnimatedNodeToView: Animated node connected to view [" + i4 + "] should be of type " + q.class.getName());
        }
        ReactApplicationContext reactApplicationContext = this.f6568e;
        if (reactApplicationContext == null) {
            throw new IllegalStateException("connectAnimatedNodeToView: Animated node could not be connected, no ReactApplicationContext: " + i4);
        }
        UIManager uIManagerI = H0.i(reactApplicationContext, i4);
        if (uIManagerI != null) {
            ((q) bVar).i(i4, uIManagerI);
            this.f6566c.put(i3, bVar);
        } else {
            ReactSoftExceptionLogger.logSoftException("NativeAnimatedNodesManager", new ReactNoCrashSoftException("connectAnimatedNodeToView: Animated node could not be connected to UIManager - uiManager disappeared for tag: " + i4));
        }
    }

    public void e(int i3, int i4) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == null) {
            throw new JSApplicationIllegalArgumentException("connectAnimatedNodes: Animated node with tag (parent) [" + i3 + "] does not exist");
        }
        b bVar2 = (b) this.f6564a.get(i4);
        if (bVar2 != null) {
            bVar.b(bVar2);
            this.f6566c.put(i4, bVar2);
        } else {
            throw new JSApplicationIllegalArgumentException("connectAnimatedNodes: Animated node with tag (child) [" + i4 + "] does not exist");
        }
    }

    public void f(int i3, ReadableMap readableMap) {
        b pVar;
        if (this.f6564a.get(i3) != null) {
            throw new JSApplicationIllegalArgumentException("createAnimatedNode: Animated node [" + i3 + "] already exists");
        }
        String string = readableMap.getString("type");
        if ("style".equals(string)) {
            pVar = new s(readableMap, this);
        } else if ("value".equals(string)) {
            pVar = new w(readableMap);
        } else if ("color".equals(string)) {
            pVar = new f(readableMap, this, this.f6568e);
        } else if ("props".equals(string)) {
            pVar = new q(readableMap, this);
        } else if ("interpolation".equals(string)) {
            pVar = new k(readableMap);
        } else if ("addition".equals(string)) {
            pVar = new com.facebook.react.animated.a(readableMap, this);
        } else if ("subtraction".equals(string)) {
            pVar = new t(readableMap, this);
        } else if ("division".equals(string)) {
            pVar = new i(readableMap, this);
        } else if ("multiplication".equals(string)) {
            pVar = new m(readableMap, this);
        } else if ("modulus".equals(string)) {
            pVar = new l(readableMap, this);
        } else if ("diffclamp".equals(string)) {
            pVar = new h(readableMap, this);
        } else if ("transform".equals(string)) {
            pVar = new v(readableMap, this);
        } else if ("tracking".equals(string)) {
            pVar = new u(readableMap, this);
        } else {
            if (!"object".equals(string)) {
                throw new JSApplicationIllegalArgumentException("Unsupported node type: " + string);
            }
            pVar = new p(readableMap, this);
        }
        pVar.f6507d = i3;
        this.f6564a.put(i3, pVar);
        this.f6566c.put(i3, pVar);
    }

    public void g(int i3, int i4) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == null) {
            throw new JSApplicationIllegalArgumentException("disconnectAnimatedNodeFromView: Animated node with tag [" + i3 + "] does not exist");
        }
        if (bVar instanceof q) {
            ((q) bVar).j(i4);
            return;
        }
        throw new JSApplicationIllegalArgumentException("disconnectAnimatedNodeFromView: Animated node connected to view [" + i4 + "] should be of type " + q.class.getName());
    }

    public void h(int i3, int i4) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == null) {
            throw new JSApplicationIllegalArgumentException("disconnectAnimatedNodes: Animated node with tag (parent) [" + i3 + "] does not exist");
        }
        b bVar2 = (b) this.f6564a.get(i4);
        if (bVar2 != null) {
            bVar.g(bVar2);
            this.f6566c.put(i4, bVar2);
        } else {
            throw new JSApplicationIllegalArgumentException("disconnectAnimatedNodes: Animated node with tag (child) [" + i4 + "] does not exist");
        }
    }

    public void i(int i3) {
        this.f6564a.remove(i3);
        this.f6566c.remove(i3);
    }

    public void j(int i3) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar != null && (bVar instanceof w)) {
            ((w) bVar).i();
            return;
        }
        throw new JSApplicationIllegalArgumentException("extractAnimatedNodeOffset: Animated node [" + i3 + "] does not exist, or is not a 'value' node");
    }

    public void k(int i3) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar != null && (bVar instanceof w)) {
            ((w) bVar).j();
            return;
        }
        throw new JSApplicationIllegalArgumentException("flattenAnimatedNodeOffset: Animated node [" + i3 + "] does not exist, or is not a 'value' node");
    }

    public b l(int i3) {
        return (b) this.f6564a.get(i3);
    }

    Set m(int i3, String str) {
        int i4;
        List list;
        HashSet hashSet = new HashSet();
        ListIterator listIterator = this.f6567d.listIterator();
        while (listIterator.hasNext()) {
            EventAnimationDriver eventAnimationDriver = (EventAnimationDriver) listIterator.next();
            if (eventAnimationDriver != null && str.equals(eventAnimationDriver.eventName) && i3 == (i4 = eventAnimationDriver.viewTag)) {
                hashSet.add(Integer.valueOf(i4));
                w wVar = eventAnimationDriver.valueNode;
                if (wVar != null && (list = wVar.f6504a) != null) {
                    Iterator it = list.iterator();
                    while (it.hasNext()) {
                        hashSet.add(Integer.valueOf(((b) it.next()).f6507d));
                    }
                }
            }
        }
        return hashSet;
    }

    public void n(int i3, Callback callback) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == null || !(bVar instanceof w)) {
            throw new JSApplicationIllegalArgumentException("getValue: Animated node with tag [" + i3 + "] does not exist or is not a 'value' node");
        }
        double dL = ((w) bVar).l();
        if (callback != null) {
            callback.invoke(Double.valueOf(dL));
        } else {
            if (this.f6568e == null) {
                return;
            }
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("tag", i3);
            writableMapCreateMap.putDouble("value", dL);
            this.f6568e.emitDeviceEvent("onNativeAnimatedModuleGetValue", writableMapCreateMap);
        }
    }

    public boolean p() {
        return this.f6565b.size() > 0 || this.f6566c.size() > 0;
    }

    public void q(int i3) {
        if (i3 == 2) {
            if (this.f6571h) {
                return;
            }
        } else if (this.f6572i) {
            return;
        }
        UIManager uIManagerG = H0.g(this.f6568e, i3);
        if (uIManagerG != null) {
            uIManagerG.getEventDispatcher().d(this);
            if (i3 == 2) {
                this.f6571h = true;
            } else {
                this.f6572i = true;
            }
        }
    }

    public void s(int i3, String str, int i4) {
        String strR = r(str);
        ListIterator listIterator = this.f6567d.listIterator();
        while (true) {
            if (!listIterator.hasNext()) {
                break;
            }
            EventAnimationDriver eventAnimationDriver = (EventAnimationDriver) listIterator.next();
            if (strR.equals(eventAnimationDriver.eventName) && i3 == eventAnimationDriver.viewTag && i4 == eventAnimationDriver.valueNode.f6507d) {
                listIterator.remove();
                break;
            }
        }
        if (strR.equals("topScroll")) {
            s(i3, "topScrollEnded", i4);
        }
    }

    public void t(int i3) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar == null) {
            return;
        }
        if (bVar instanceof q) {
            ((q) bVar).l();
            return;
        }
        throw new JSApplicationIllegalArgumentException("Animated node connected to view [?] should be of type " + q.class.getName());
    }

    public void u(long j3) {
        UiThreadUtil.assertOnUiThread();
        for (int i3 = 0; i3 < this.f6566c.size(); i3++) {
            this.f6570g.add((b) this.f6566c.valueAt(i3));
        }
        this.f6566c.clear();
        boolean z3 = false;
        for (int i4 = 0; i4 < this.f6565b.size(); i4++) {
            e eVar = (e) this.f6565b.valueAt(i4);
            eVar.b(j3);
            this.f6570g.add(eVar.f6509b);
            if (eVar.f6508a) {
                z3 = true;
            }
        }
        D(this.f6570g);
        this.f6570g.clear();
        if (z3) {
            WritableArray writableArrayCreateArray = null;
            for (int size = this.f6565b.size() - 1; size >= 0; size--) {
                e eVar2 = (e) this.f6565b.valueAt(size);
                if (eVar2.f6508a) {
                    if (eVar2.f6510c != null) {
                        WritableMap writableMapCreateMap = Arguments.createMap();
                        writableMapCreateMap.putBoolean("finished", true);
                        writableMapCreateMap.putDouble("value", eVar2.f6509b.f6621f);
                        eVar2.f6510c.invoke(writableMapCreateMap);
                    } else if (this.f6568e != null) {
                        WritableMap writableMapCreateMap2 = Arguments.createMap();
                        writableMapCreateMap2.putInt("animationId", eVar2.f6511d);
                        writableMapCreateMap2.putBoolean("finished", true);
                        writableMapCreateMap2.putDouble("value", eVar2.f6509b.f6621f);
                        if (writableArrayCreateArray == null) {
                            writableArrayCreateArray = Arguments.createArray();
                        }
                        writableArrayCreateArray.pushMap(writableMapCreateMap2);
                    }
                    this.f6565b.removeAt(size);
                }
            }
            if (writableArrayCreateArray != null) {
                this.f6568e.emitDeviceEvent("onNativeAnimatedModuleAnimationFinished", writableArrayCreateArray);
            }
        }
    }

    public void v(int i3, double d3) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar != null && (bVar instanceof w)) {
            ((w) bVar).f6622g = d3;
            this.f6566c.put(i3, bVar);
        } else {
            throw new JSApplicationIllegalArgumentException("setAnimatedNodeOffset: Animated node [" + i3 + "] does not exist, or is not a 'value' node");
        }
    }

    public void w(int i3, double d3) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar != null && (bVar instanceof w)) {
            A(bVar);
            ((w) bVar).f6621f = d3;
            this.f6566c.put(i3, bVar);
        } else {
            throw new JSApplicationIllegalArgumentException("setAnimatedNodeValue: Animated node [" + i3 + "] does not exist, or is not a 'value' node");
        }
    }

    public void x(int i3, int i4, ReadableMap readableMap, Callback callback) {
        e gVar;
        b bVar = (b) this.f6564a.get(i4);
        if (bVar == null) {
            throw new JSApplicationIllegalArgumentException("startAnimatingNode: Animated node [" + i4 + "] does not exist");
        }
        if (!(bVar instanceof w)) {
            throw new JSApplicationIllegalArgumentException("startAnimatingNode: Animated node [" + i4 + "] should be of type " + w.class.getName());
        }
        e eVar = (e) this.f6565b.get(i3);
        if (eVar != null) {
            eVar.a(readableMap);
            return;
        }
        String string = readableMap.getString("type");
        if ("frames".equals(string)) {
            gVar = new j(readableMap);
        } else if ("spring".equals(string)) {
            gVar = new r(readableMap);
        } else {
            if (!"decay".equals(string)) {
                throw new JSApplicationIllegalArgumentException("startAnimatingNode: Unsupported animation type [" + i4 + "]: " + string);
            }
            gVar = new g(readableMap);
        }
        gVar.f6511d = i3;
        gVar.f6510c = callback;
        gVar.f6509b = (w) bVar;
        this.f6565b.put(i3, gVar);
    }

    public void y(int i3, c cVar) {
        b bVar = (b) this.f6564a.get(i3);
        if (bVar != null && (bVar instanceof w)) {
            ((w) bVar).n(cVar);
            return;
        }
        throw new JSApplicationIllegalArgumentException("startListeningToAnimatedNodeValue: Animated node [" + i3 + "] does not exist, or is not a 'value' node");
    }

    public void z(int i3) {
        WritableArray writableArrayCreateArray;
        int i4 = 0;
        while (true) {
            writableArrayCreateArray = null;
            if (i4 >= this.f6565b.size()) {
                break;
            }
            e eVar = (e) this.f6565b.valueAt(i4);
            if (eVar.f6511d == i3) {
                if (eVar.f6510c != null) {
                    WritableMap writableMapCreateMap = Arguments.createMap();
                    writableMapCreateMap.putBoolean("finished", false);
                    writableMapCreateMap.putDouble("value", eVar.f6509b.f6621f);
                    eVar.f6510c.invoke(writableMapCreateMap);
                } else if (this.f6568e != null) {
                    WritableMap writableMapCreateMap2 = Arguments.createMap();
                    writableMapCreateMap2.putInt("animationId", eVar.f6511d);
                    writableMapCreateMap2.putBoolean("finished", false);
                    writableMapCreateMap2.putDouble("value", eVar.f6509b.f6621f);
                    writableArrayCreateArray = Arguments.createArray();
                    writableArrayCreateArray.pushMap(writableMapCreateMap2);
                }
                this.f6565b.removeAt(i4);
            } else {
                i4++;
            }
        }
        if (writableArrayCreateArray != null) {
            this.f6568e.emitDeviceEvent("onNativeAnimatedModuleAnimationFinished", writableArrayCreateArray);
        }
    }
}
