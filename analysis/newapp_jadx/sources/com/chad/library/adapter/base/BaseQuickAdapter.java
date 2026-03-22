package com.chad.library.adapter.base;

import android.animation.Animator;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.IdRes;
import androidx.annotation.IntRange;
import androidx.annotation.LayoutRes;
import androidx.annotation.NonNull;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.diff.BrvahListUpdateCallback;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.GenericSignatureFormatError;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.MalformedParameterizedTypeException;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p072h.C1285a;
import p005b.p067b.p068a.p069a.p070a.p072h.C1287c;
import p005b.p067b.p068a.p069a.p070a.p072h.C1288d;
import p005b.p067b.p068a.p069a.p070a.p072h.C1289e;
import p005b.p067b.p068a.p069a.p070a.p072h.C1290f;
import p005b.p067b.p068a.p069a.p070a.p072h.InterfaceC1286b;
import p005b.p067b.p068a.p069a.p070a.p073i.C1293c;
import p005b.p067b.p068a.p069a.p070a.p073i.C1294d;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1301a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1303c;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1306f;
import p005b.p067b.p068a.p069a.p070a.p077l.EnumC1311b;
import p005b.p067b.p068a.p069a.p070a.p078m.C1316d;
import p005b.p067b.p068a.p069a.p070a.p078m.C1317e;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p067b.p068a.p069a.p070a.p078m.C1319g;
import p005b.p067b.p068a.p069a.p070a.p078m.InterfaceC1320h;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u009a\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010!\n\u0000\n\u0002\u0010\t\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0015\n\u0002\b-\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0010\u001e\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\u0015\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b!\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\b&\u0018\u0000 \u0097\u0002*\u0004\b\u0000\u0010\u0001*\b\b\u0001\u0010\u0003*\u00020\u00022\b\u0012\u0004\u0012\u00028\u00010\u00042\u00020\u00052\u00020\u0005:\u0004\u0098\u0002\u0099\u0002B'\b\u0007\u0012\b\b\u0001\u0010S\u001a\u00020\u001d\u0012\u0010\b\u0002\u0010x\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010+¢\u0006\u0006\b\u0095\u0002\u0010\u0096\u0002J\u000f\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\u0007\u0010\bJ!\u0010\u000b\u001a\b\u0012\u0002\b\u0003\u0018\u00010\t2\n\u0010\n\u001a\u0006\u0012\u0002\b\u00030\tH\u0002¢\u0006\u0004\b\u000b\u0010\fJ%\u0010\u000f\u001a\u0004\u0018\u00018\u00012\n\u0010\n\u001a\u0006\u0012\u0002\b\u00030\t2\u0006\u0010\u000e\u001a\u00020\rH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u0017\u0010\u0013\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00020\u0011H\u0002¢\u0006\u0004\b\u0013\u0010\u0014J\u001f\u0010\u0017\u001a\u00020\u00062\u0006\u0010\u0015\u001a\u00028\u00012\u0006\u0010\u0016\u001a\u00028\u0000H$¢\u0006\u0004\b\u0017\u0010\u0018J-\u0010\u0017\u001a\u00020\u00062\u0006\u0010\u0015\u001a\u00028\u00012\u0006\u0010\u0016\u001a\u00028\u00002\f\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00050\u0019H\u0014¢\u0006\u0004\b\u0017\u0010\u001bJ\u001f\u0010\u001f\u001a\u00020\u00062\u0006\u0010\u001c\u001a\u00028\u00012\u0006\u0010\u001e\u001a\u00020\u001dH\u0014¢\u0006\u0004\b\u001f\u0010 J\u001f\u0010#\u001a\u00028\u00012\u0006\u0010\"\u001a\u00020!2\u0006\u0010\u001e\u001a\u00020\u001dH\u0016¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u00020\u001dH\u0016¢\u0006\u0004\b%\u0010&J\u0017\u0010(\u001a\u00020\u001d2\u0006\u0010'\u001a\u00020\u001dH\u0016¢\u0006\u0004\b(\u0010)J\u001f\u0010*\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00028\u00012\u0006\u0010'\u001a\u00020\u001dH\u0016¢\u0006\u0004\b*\u0010 J-\u0010*\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00028\u00012\u0006\u0010'\u001a\u00020\u001d2\f\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00050+H\u0016¢\u0006\u0004\b*\u0010,J\u0017\u0010.\u001a\u00020-2\u0006\u0010'\u001a\u00020\u001dH\u0016¢\u0006\u0004\b.\u0010/J\u0017\u00100\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00028\u0001H\u0016¢\u0006\u0004\b0\u00101J\u0017\u00104\u001a\u00020\u00062\u0006\u00103\u001a\u000202H\u0016¢\u0006\u0004\b4\u00105J\u0017\u00108\u001a\u0002072\u0006\u00106\u001a\u00020\u001dH\u0014¢\u0006\u0004\b8\u00109J\u0019\u0010:\u001a\u00028\u00002\b\b\u0001\u0010'\u001a\u00020\u001dH\u0016¢\u0006\u0004\b:\u0010;J\u001b\u0010<\u001a\u0004\u0018\u00018\u00002\b\b\u0001\u0010'\u001a\u00020\u001dH\u0016¢\u0006\u0004\b<\u0010;J\u0019\u0010=\u001a\u00020\u001d2\b\u0010\u0016\u001a\u0004\u0018\u00018\u0000H\u0016¢\u0006\u0004\b=\u0010>J\u0013\u0010@\u001a\b\u0012\u0004\u0012\u00020\u001d0?¢\u0006\u0004\b@\u0010AJ\u001b\u0010D\u001a\u00020\u00062\f\b\u0001\u0010C\u001a\u00020B\"\u00020\u001d¢\u0006\u0004\bD\u0010EJ\u0013\u0010F\u001a\b\u0012\u0004\u0012\u00020\u001d0?¢\u0006\u0004\bF\u0010AJ\u001b\u0010G\u001a\u00020\u00062\f\b\u0001\u0010C\u001a\u00020B\"\u00020\u001d¢\u0006\u0004\bG\u0010EJ\u001f\u0010H\u001a\u00020\u00062\u0006\u0010\u001c\u001a\u00028\u00012\u0006\u0010\u001e\u001a\u00020\u001dH\u0014¢\u0006\u0004\bH\u0010 J\u001f\u0010J\u001a\u00020\u00062\u0006\u0010I\u001a\u00020\r2\u0006\u0010'\u001a\u00020\u001dH\u0014¢\u0006\u0004\bJ\u0010KJ\u001f\u0010L\u001a\u0002072\u0006\u0010I\u001a\u00020\r2\u0006\u0010'\u001a\u00020\u001dH\u0014¢\u0006\u0004\bL\u0010MJ\u001f\u0010N\u001a\u00020\u00062\u0006\u0010I\u001a\u00020\r2\u0006\u0010'\u001a\u00020\u001dH\u0014¢\u0006\u0004\bN\u0010KJ\u001f\u0010O\u001a\u0002072\u0006\u0010I\u001a\u00020\r2\u0006\u0010'\u001a\u00020\u001dH\u0014¢\u0006\u0004\bO\u0010MJ\u000f\u0010P\u001a\u00020\u001dH\u0014¢\u0006\u0004\bP\u0010&J\u0017\u0010Q\u001a\u00020\u001d2\u0006\u0010'\u001a\u00020\u001dH\u0014¢\u0006\u0004\bQ\u0010)J\u001f\u0010R\u001a\u00028\u00012\u0006\u0010\"\u001a\u00020!2\u0006\u0010\u001e\u001a\u00020\u001dH\u0014¢\u0006\u0004\bR\u0010$J!\u0010T\u001a\u00028\u00012\u0006\u0010\"\u001a\u00020!2\b\b\u0001\u0010S\u001a\u00020\u001dH\u0014¢\u0006\u0004\bT\u0010$J\u0017\u0010T\u001a\u00028\u00012\u0006\u0010\u000e\u001a\u00020\rH\u0014¢\u0006\u0004\bT\u0010UJ\u0017\u0010V\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00020\u0011H\u0014¢\u0006\u0004\bV\u0010\u0014J!\u0010X\u001a\u0004\u0018\u00010\r2\u0006\u0010'\u001a\u00020\u001d2\b\b\u0001\u0010W\u001a\u00020\u001d¢\u0006\u0004\bX\u0010YJ+\u0010\\\u001a\u00020\u001d2\u0006\u0010\u000e\u001a\u00020\r2\b\b\u0002\u0010Z\u001a\u00020\u001d2\b\b\u0002\u0010[\u001a\u00020\u001dH\u0007¢\u0006\u0004\b\\\u0010]J+\u0010^\u001a\u00020\u001d2\u0006\u0010\u000e\u001a\u00020\r2\b\b\u0002\u0010Z\u001a\u00020\u001d2\b\b\u0002\u0010[\u001a\u00020\u001dH\u0007¢\u0006\u0004\b^\u0010]J\r\u0010_\u001a\u000207¢\u0006\u0004\b_\u0010`J\u0015\u0010b\u001a\u00020\u00062\u0006\u0010a\u001a\u00020\r¢\u0006\u0004\bb\u0010cJ\r\u0010d\u001a\u00020\u0006¢\u0006\u0004\bd\u0010\bJ+\u0010e\u001a\u00020\u001d2\u0006\u0010\u000e\u001a\u00020\r2\b\b\u0002\u0010Z\u001a\u00020\u001d2\b\b\u0002\u0010[\u001a\u00020\u001dH\u0007¢\u0006\u0004\be\u0010]J+\u0010f\u001a\u00020\u001d2\u0006\u0010\u000e\u001a\u00020\r2\b\b\u0002\u0010Z\u001a\u00020\u001d2\b\b\u0002\u0010[\u001a\u00020\u001dH\u0007¢\u0006\u0004\bf\u0010]J\u0015\u0010h\u001a\u00020\u00062\u0006\u0010g\u001a\u00020\r¢\u0006\u0004\bh\u0010cJ\r\u0010i\u001a\u00020\u0006¢\u0006\u0004\bi\u0010\bJ\r\u0010j\u001a\u000207¢\u0006\u0004\bj\u0010`J\u0015\u0010l\u001a\u00020\u00062\u0006\u0010k\u001a\u00020\r¢\u0006\u0004\bl\u0010cJ\u0015\u0010l\u001a\u00020\u00062\u0006\u0010S\u001a\u00020\u001d¢\u0006\u0004\bl\u0010mJ\r\u0010n\u001a\u00020\u0006¢\u0006\u0004\bn\u0010\bJ\r\u0010o\u001a\u000207¢\u0006\u0004\bo\u0010`J\u001f\u0010r\u001a\u00020\u00062\u0006\u0010q\u001a\u00020p2\u0006\u0010Z\u001a\u00020\u001dH\u0014¢\u0006\u0004\br\u0010sJ\u0015\u0010v\u001a\u00020\u00062\u0006\u0010u\u001a\u00020t¢\u0006\u0004\bv\u0010wJ\u001f\u0010y\u001a\u00020\u00062\u000e\u0010x\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010+H\u0016¢\u0006\u0004\by\u0010zJ\u001f\u0010{\u001a\u00020\u00062\u000e\u0010x\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u0019H\u0016¢\u0006\u0004\b{\u0010zJ!\u0010|\u001a\u00020\u00062\b\b\u0001\u0010'\u001a\u00020\u001d2\u0006\u0010x\u001a\u00028\u0000H\u0016¢\u0006\u0004\b|\u0010}J\u0019\u0010|\u001a\u00020\u00062\b\b\u0001\u0010x\u001a\u00028\u0000H\u0016¢\u0006\u0004\b|\u0010~J)\u0010|\u001a\u00020\u00062\b\b\u0001\u0010'\u001a\u00020\u001d2\r\u0010\u0080\u0001\u001a\b\u0012\u0004\u0012\u00028\u00000\u007fH\u0016¢\u0006\u0005\b|\u0010\u0081\u0001J!\u0010|\u001a\u00020\u00062\u000f\b\u0001\u0010\u0080\u0001\u001a\b\u0012\u0004\u0012\u00028\u00000\u007fH\u0016¢\u0006\u0005\b|\u0010\u0082\u0001J\u001b\u0010\u0083\u0001\u001a\u00020\u00062\b\b\u0001\u0010'\u001a\u00020\u001dH\u0016¢\u0006\u0005\b\u0083\u0001\u0010mJ\u0019\u0010\u0083\u0001\u001a\u00020\u00062\u0006\u0010x\u001a\u00028\u0000H\u0016¢\u0006\u0005\b\u0083\u0001\u0010~J#\u0010\u0084\u0001\u001a\u00020\u00062\b\b\u0001\u0010Z\u001a\u00020\u001d2\u0006\u0010x\u001a\u00028\u0000H\u0016¢\u0006\u0005\b\u0084\u0001\u0010}J!\u0010\u0085\u0001\u001a\u00020\u00062\r\u0010\u0080\u0001\u001a\b\u0012\u0004\u0012\u00028\u00000\u007fH\u0016¢\u0006\u0006\b\u0085\u0001\u0010\u0082\u0001J\u001a\u0010\u0087\u0001\u001a\u00020\u00062\u0007\u0010\u0086\u0001\u001a\u00020\u001dH\u0004¢\u0006\u0005\b\u0087\u0001\u0010mJ \u0010\u008a\u0001\u001a\u00020\u00062\u000e\u0010\u0089\u0001\u001a\t\u0012\u0004\u0012\u00028\u00000\u0088\u0001¢\u0006\u0006\b\u008a\u0001\u0010\u008b\u0001J \u0010\u008e\u0001\u001a\u00020\u00062\u000e\u0010\u008d\u0001\u001a\t\u0012\u0004\u0012\u00028\u00000\u008c\u0001¢\u0006\u0006\b\u008e\u0001\u0010\u008f\u0001J\u0017\u0010\u0091\u0001\u001a\t\u0012\u0004\u0012\u00028\u00000\u0090\u0001¢\u0006\u0006\b\u0091\u0001\u0010\u0092\u0001J\"\u0010\u0093\u0001\u001a\u00020\u00062\u000f\u0010\u0080\u0001\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010+H\u0016¢\u0006\u0005\b\u0093\u0001\u0010zJ-\u0010\u0093\u0001\u001a\u00020\u00062\n\b\u0001\u0010\u0095\u0001\u001a\u00030\u0094\u00012\r\u0010\u0080\u0001\u001a\b\u0012\u0004\u0012\u00028\u00000+H\u0016¢\u0006\u0006\b\u0093\u0001\u0010\u0096\u0001J\u001e\u0010\u0099\u0001\u001a\u00020\u00062\n\u0010\u0098\u0001\u001a\u0005\u0018\u00010\u0097\u0001H\u0016¢\u0006\u0006\b\u0099\u0001\u0010\u009a\u0001J\u001e\u0010\u009d\u0001\u001a\u00020\u00062\n\u0010\u009c\u0001\u001a\u0005\u0018\u00010\u009b\u0001H\u0016¢\u0006\u0006\b\u009d\u0001\u0010\u009e\u0001J\u001e\u0010 \u0001\u001a\u00020\u00062\n\u0010\u009c\u0001\u001a\u0005\u0018\u00010\u009f\u0001H\u0016¢\u0006\u0006\b \u0001\u0010¡\u0001J\u001e\u0010£\u0001\u001a\u00020\u00062\n\u0010\u009c\u0001\u001a\u0005\u0018\u00010¢\u0001H\u0016¢\u0006\u0006\b£\u0001\u0010¤\u0001J\u001e\u0010¦\u0001\u001a\u00020\u00062\n\u0010\u009c\u0001\u001a\u0005\u0018\u00010¥\u0001H\u0016¢\u0006\u0006\b¦\u0001\u0010§\u0001J\u0013\u0010¨\u0001\u001a\u0005\u0018\u00010\u009b\u0001¢\u0006\u0006\b¨\u0001\u0010©\u0001J\u0013\u0010ª\u0001\u001a\u0005\u0018\u00010\u009f\u0001¢\u0006\u0006\bª\u0001\u0010«\u0001J\u0013\u0010¬\u0001\u001a\u0005\u0018\u00010¢\u0001¢\u0006\u0006\b¬\u0001\u0010\u00ad\u0001J\u0013\u0010®\u0001\u001a\u0005\u0018\u00010¥\u0001¢\u0006\u0006\b®\u0001\u0010¯\u0001R(\u0010°\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\b°\u0001\u0010±\u0001\u001a\u0005\b²\u0001\u0010`\"\u0006\b³\u0001\u0010´\u0001R(\u0010µ\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bµ\u0001\u0010±\u0001\u001a\u0005\b¶\u0001\u0010`\"\u0006\b·\u0001\u0010´\u0001R\u0019\u0010»\u0001\u001a\u0005\u0018\u00010¸\u00018F@\u0006¢\u0006\b\u001a\u0006\b¹\u0001\u0010º\u0001R\u001a\u0010¼\u0001\u001a\u00030¸\u00018\u0002@\u0002X\u0082.¢\u0006\b\n\u0006\b¼\u0001\u0010½\u0001R(\u0010¾\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\b¾\u0001\u0010±\u0001\u001a\u0005\b¾\u0001\u0010`\"\u0006\b¿\u0001\u0010´\u0001R\u0015\u0010Á\u0001\u001a\u00020\u001d8F@\u0006¢\u0006\u0007\u001a\u0005\bÀ\u0001\u0010&R\"\u0010Â\u0001\u001a\u000b\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u0090\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bÂ\u0001\u0010Ã\u0001R\u0019\u0010Å\u0001\u001a\u0005\u0018\u00010¸\u00018F@\u0006¢\u0006\b\u001a\u0006\bÄ\u0001\u0010º\u0001R(\u0010Æ\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bÆ\u0001\u0010±\u0001\u001a\u0005\bÆ\u0001\u0010`\"\u0006\bÇ\u0001\u0010´\u0001R\u001f\u0010È\u0001\u001a\b\u0012\u0004\u0012\u00020\u001d0?8\u0002@\u0002X\u0082\u0004¢\u0006\b\n\u0006\bÈ\u0001\u0010É\u0001R\u0017\u0010S\u001a\u00020\u001d8\u0002@\u0002X\u0082\u0004¢\u0006\u0007\n\u0005\bS\u0010Ê\u0001R\u001c\u0010Ë\u0001\u001a\u0005\u0018\u00010¥\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bË\u0001\u0010Ì\u0001R\u001a\u0010Í\u0001\u001a\u00030¸\u00018\u0002@\u0002X\u0082.¢\u0006\b\n\u0006\bÍ\u0001\u0010½\u0001R\u001a\u0010Ï\u0001\u001a\u00030Î\u00018\u0002@\u0002X\u0082.¢\u0006\b\n\u0006\bÏ\u0001\u0010Ð\u0001R(\u0010Ñ\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bÑ\u0001\u0010±\u0001\u001a\u0005\bÒ\u0001\u0010`\"\u0006\bÓ\u0001\u0010´\u0001R0\u0010Ö\u0001\u001a\u0005\u0018\u00010Ô\u00012\n\u0010Õ\u0001\u001a\u0005\u0018\u00010Ô\u00018\u0006@BX\u0086\u000e¢\u0006\u0010\n\u0006\bÖ\u0001\u0010×\u0001\u001a\u0006\bØ\u0001\u0010Ù\u0001R0\u0010Û\u0001\u001a\u0005\u0018\u00010Ú\u00012\n\u0010Õ\u0001\u001a\u0005\u0018\u00010Ú\u00018\u0006@BX\u0086\u000e¢\u0006\u0010\n\u0006\bÛ\u0001\u0010Ü\u0001\u001a\u0006\bÝ\u0001\u0010Þ\u0001R\u0019\u0010ß\u0001\u001a\u00020\u001d8\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bß\u0001\u0010Ê\u0001R(\u0010à\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bà\u0001\u0010±\u0001\u001a\u0005\bá\u0001\u0010`\"\u0006\bâ\u0001\u0010´\u0001R\u001c\u0010ã\u0001\u001a\u0005\u0018\u00010¢\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bã\u0001\u0010ä\u0001R(\u0010å\u0001\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0017\n\u0006\bå\u0001\u0010±\u0001\u001a\u0005\bæ\u0001\u0010`\"\u0006\bç\u0001\u0010´\u0001R;\u0010x\u001a\b\u0012\u0004\u0012\u00028\u00000+2\r\u0010Õ\u0001\u001a\b\u0012\u0004\u0012\u00028\u00000+8\u0006@@X\u0086\u000e¢\u0006\u0016\n\u0005\bx\u0010è\u0001\u001a\u0006\bé\u0001\u0010ê\u0001\"\u0005\bë\u0001\u0010zR\u0015\u0010í\u0001\u001a\u00020\u001d8F@\u0006¢\u0006\u0007\u001a\u0005\bì\u0001\u0010&R\u0015\u0010ï\u0001\u001a\u00020\u001d8F@\u0006¢\u0006\u0007\u001a\u0005\bî\u0001\u0010&R\u0019\u0010ò\u0001\u001a\u0005\u0018\u00010Î\u00018F@\u0006¢\u0006\b\u001a\u0006\bð\u0001\u0010ñ\u0001R\u0015\u0010ô\u0001\u001a\u00020\u001d8F@\u0006¢\u0006\u0007\u001a\u0005\bó\u0001\u0010&R\u001f\u0010õ\u0001\u001a\b\u0012\u0004\u0012\u00020\u001d0?8\u0002@\u0002X\u0082\u0004¢\u0006\b\n\u0006\bõ\u0001\u0010É\u0001R\u001c\u0010ö\u0001\u001a\u0005\u0018\u00010\u009b\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bö\u0001\u0010÷\u0001R\u001c\u0010ø\u0001\u001a\u0005\u0018\u00010\u0097\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bø\u0001\u0010ù\u0001R\u001c\u0010ú\u0001\u001a\u0005\u0018\u00010\u009f\u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\bú\u0001\u0010û\u0001R0\u0010ý\u0001\u001a\t\u0012\u0004\u0012\u0002020ü\u00018\u0006@\u0006X\u0086.¢\u0006\u0018\n\u0006\bý\u0001\u0010þ\u0001\u001a\u0006\bÿ\u0001\u0010\u0080\u0002\"\u0006\b\u0081\u0002\u0010\u0082\u0002R8\u0010\u0085\u0002\u001a\u0005\u0018\u00010\u0083\u00022\n\u0010\u0084\u0002\u001a\u0005\u0018\u00010\u0083\u00028\u0006@FX\u0086\u000e¢\u0006\u0018\n\u0006\b\u0085\u0002\u0010\u0086\u0002\u001a\u0006\b\u0087\u0002\u0010\u0088\u0002\"\u0006\b\u0089\u0002\u0010\u008a\u0002R0\u0010\u008c\u0002\u001a\u0005\u0018\u00010\u008b\u00022\n\u0010Õ\u0001\u001a\u0005\u0018\u00010\u008b\u00028\u0006@BX\u0086\u000e¢\u0006\u0010\n\u0006\b\u008c\u0002\u0010\u008d\u0002\u001a\u0006\b\u008e\u0002\u0010\u008f\u0002R,\u0010\u0091\u0002\u001a\u00030\u0090\u00022\b\u0010Õ\u0001\u001a\u00030\u0090\u00028\u0004@BX\u0084.¢\u0006\u0010\n\u0006\b\u0091\u0002\u0010\u0092\u0002\u001a\u0006\b\u0093\u0002\u0010\u0094\u0002¨\u0006\u009a\u0002"}, m5311d2 = {"Lcom/chad/library/adapter/base/BaseQuickAdapter;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "VH", "Landroidx/recyclerview/widget/RecyclerView$Adapter;", "", "", "checkModule", "()V", "Ljava/lang/Class;", "z", "getInstancedGenericKClass", "(Ljava/lang/Class;)Ljava/lang/Class;", "Landroid/view/View;", "view", "createBaseGenericKInstance", "(Ljava/lang/Class;Landroid/view/View;)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "holder", "addAnimation", "(Landroidx/recyclerview/widget/RecyclerView$ViewHolder;)V", "helper", "item", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;)V", "", "payloads", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;Ljava/util/List;)V", "viewHolder", "", "viewType", "onItemViewHolderCreated", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;I)V", "Landroid/view/ViewGroup;", "parent", "onCreateViewHolder", "(Landroid/view/ViewGroup;I)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "getItemCount", "()I", "position", "getItemViewType", "(I)I", "onBindViewHolder", "", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;ILjava/util/List;)V", "", "getItemId", "(I)J", "onViewAttachedToWindow", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;)V", "Landroidx/recyclerview/widget/RecyclerView;", "recyclerView", "onAttachedToRecyclerView", "(Landroidx/recyclerview/widget/RecyclerView;)V", "type", "", "isFixedViewType", "(I)Z", "getItem", "(I)Ljava/lang/Object;", "getItemOrNull", "getItemPosition", "(Ljava/lang/Object;)I", "Ljava/util/LinkedHashSet;", "getChildClickViewIds", "()Ljava/util/LinkedHashSet;", "", "viewIds", "addChildClickViewIds", "([I)V", "getChildLongClickViewIds", "addChildLongClickViewIds", "bindViewClickListener", "v", "setOnItemClick", "(Landroid/view/View;I)V", "setOnItemLongClick", "(Landroid/view/View;I)Z", "setOnItemChildClick", "setOnItemChildLongClick", "getDefItemCount", "getDefItemViewType", "onCreateDefViewHolder", "layoutResId", "createBaseViewHolder", "(Landroid/view/View;)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "setFullSpan", "viewId", "getViewByPosition", "(II)Landroid/view/View;", "index", "orientation", "addHeaderView", "(Landroid/view/View;II)I", "setHeaderView", "hasHeaderLayout", "()Z", "header", "removeHeaderView", "(Landroid/view/View;)V", "removeAllHeaderView", "addFooterView", "setFooterView", "footer", "removeFooterView", "removeAllFooterView", "hasFooterLayout", "emptyView", "setEmptyView", "(I)V", "removeEmptyView", "hasEmptyView", "Landroid/animation/Animator;", "anim", "startAnim", "(Landroid/animation/Animator;I)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter$a;", "animationType", "setAnimationWithDefault", "(Lcom/chad/library/adapter/base/BaseQuickAdapter$a;)V", "data", "setNewData", "(Ljava/util/List;)V", "setNewData2", "addData", "(ILjava/lang/Object;)V", "(Ljava/lang/Object;)V", "", "newData", "(ILjava/util/Collection;)V", "(Ljava/util/Collection;)V", "remove", "setData", "replaceData", "size", "compatibilityDataSizeChanged", "Landroidx/recyclerview/widget/DiffUtil$ItemCallback;", "diffCallback", "setDiffCallback", "(Landroidx/recyclerview/widget/DiffUtil$ItemCallback;)V", "Lb/b/a/a/a/i/d;", "config", "setDiffConfig", "(Lb/b/a/a/a/i/d;)V", "Lb/b/a/a/a/i/c;", "getDiffHelper", "()Lb/b/a/a/a/i/c;", "setDiffNewData", "Landroidx/recyclerview/widget/DiffUtil$DiffResult;", "diffResult", "(Landroidx/recyclerview/widget/DiffUtil$DiffResult;Ljava/util/List;)V", "Lb/b/a/a/a/k/a;", "spanSizeLookup", "setGridSpanSizeLookup", "(Lb/b/a/a/a/k/a;)V", "Lb/b/a/a/a/k/d;", "listener", "setOnItemClickListener", "(Lb/b/a/a/a/k/d;)V", "Lb/b/a/a/a/k/f;", "setOnItemLongClickListener", "(Lb/b/a/a/a/k/f;)V", "Lb/b/a/a/a/k/b;", "setOnItemChildClickListener", "(Lb/b/a/a/a/k/b;)V", "Lb/b/a/a/a/k/c;", "setOnItemChildLongClickListener", "(Lb/b/a/a/a/k/c;)V", "getOnItemClickListener", "()Lb/b/a/a/a/k/d;", "getOnItemLongClickListener", "()Lb/b/a/a/a/k/f;", "getOnItemChildClickListener", "()Lb/b/a/a/a/k/b;", "getOnItemChildLongClickListener", "()Lb/b/a/a/a/k/c;", "footerViewAsFlow", "Z", "getFooterViewAsFlow", "setFooterViewAsFlow", "(Z)V", "animationEnable", "getAnimationEnable", "setAnimationEnable", "Landroid/widget/LinearLayout;", "getHeaderLayout", "()Landroid/widget/LinearLayout;", "headerLayout", "mHeaderLayout", "Landroid/widget/LinearLayout;", "isAnimationFirstOnly", "setAnimationFirstOnly", "getHeaderLayoutCount", "headerLayoutCount", "mDiffHelper", "Lb/b/a/a/a/i/c;", "getFooterLayout", "footerLayout", "isUseEmpty", "setUseEmpty", "childClickViewIds", "Ljava/util/LinkedHashSet;", "I", "mOnItemChildLongClickListener", "Lb/b/a/a/a/k/c;", "mFooterLayout", "Landroid/widget/FrameLayout;", "mEmptyLayout", "Landroid/widget/FrameLayout;", "headerWithEmptyEnable", "getHeaderWithEmptyEnable", "setHeaderWithEmptyEnable", "Lb/b/a/a/a/m/f;", "<set-?>", "loadMoreModule", "Lb/b/a/a/a/m/f;", "getLoadMoreModule", "()Lb/b/a/a/a/m/f;", "Lb/b/a/a/a/m/d;", "draggableModule", "Lb/b/a/a/a/m/d;", "getDraggableModule", "()Lb/b/a/a/a/m/d;", "mLastPosition", "headerViewAsFlow", "getHeaderViewAsFlow", "setHeaderViewAsFlow", "mOnItemChildClickListener", "Lb/b/a/a/a/k/b;", "footerWithEmptyEnable", "getFooterWithEmptyEnable", "setFooterWithEmptyEnable", "Ljava/util/List;", "getData", "()Ljava/util/List;", "setData$com_github_CymChad_brvah", "getFooterLayoutCount", "footerLayoutCount", "getHeaderViewPosition", "headerViewPosition", "getEmptyLayout", "()Landroid/widget/FrameLayout;", "emptyLayout", "getFooterViewPosition", "footerViewPosition", "childLongClickViewIds", "mOnItemClickListener", "Lb/b/a/a/a/k/d;", "mSpanSizeLookup", "Lb/b/a/a/a/k/a;", "mOnItemLongClickListener", "Lb/b/a/a/a/k/f;", "Ljava/lang/ref/WeakReference;", "weakRecyclerView", "Ljava/lang/ref/WeakReference;", "getWeakRecyclerView", "()Ljava/lang/ref/WeakReference;", "setWeakRecyclerView", "(Ljava/lang/ref/WeakReference;)V", "Lb/b/a/a/a/h/b;", "value", "adapterAnimation", "Lb/b/a/a/a/h/b;", "getAdapterAnimation", "()Lb/b/a/a/a/h/b;", "setAdapterAnimation", "(Lb/b/a/a/a/h/b;)V", "Lb/b/a/a/a/m/g;", "upFetchModule", "Lb/b/a/a/a/m/g;", "getUpFetchModule", "()Lb/b/a/a/a/m/g;", "Landroid/content/Context;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "<init>", "(ILjava/util/List;)V", "Companion", "a", "b", "com.github.CymChad.brvah"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public abstract class BaseQuickAdapter<T, VH extends BaseViewHolder> extends RecyclerView.Adapter<VH> {
    public static final int EMPTY_VIEW = 268436821;
    public static final int FOOTER_VIEW = 268436275;
    public static final int HEADER_VIEW = 268435729;
    public static final int LOAD_MORE_VIEW = 268436002;

    @Nullable
    private InterfaceC1286b adapterAnimation;
    private boolean animationEnable;

    @NotNull
    private final LinkedHashSet<Integer> childClickViewIds;

    @NotNull
    private final LinkedHashSet<Integer> childLongClickViewIds;
    private Context context;

    @NotNull
    private List<T> data;

    @Nullable
    private C1316d draggableModule;
    private boolean footerViewAsFlow;
    private boolean footerWithEmptyEnable;
    private boolean headerViewAsFlow;
    private boolean headerWithEmptyEnable;
    private boolean isAnimationFirstOnly;
    private boolean isUseEmpty;
    private final int layoutResId;

    @Nullable
    private C1318f loadMoreModule;

    @Nullable
    private C1293c<T> mDiffHelper;
    private FrameLayout mEmptyLayout;
    private LinearLayout mFooterLayout;
    private LinearLayout mHeaderLayout;
    private int mLastPosition;

    @Nullable
    private InterfaceC1302b mOnItemChildClickListener;

    @Nullable
    private InterfaceC1303c mOnItemChildLongClickListener;

    @Nullable
    private InterfaceC1304d mOnItemClickListener;

    @Nullable
    private InterfaceC1306f mOnItemLongClickListener;

    @Nullable
    private InterfaceC1301a mSpanSizeLookup;

    @Nullable
    private C1319g upFetchModule;
    public WeakReference<RecyclerView> weakRecyclerView;

    /* renamed from: com.chad.library.adapter.base.BaseQuickAdapter$a */
    public enum EnumC3227a {
        AlphaIn,
        ScaleIn,
        SlideInBottom,
        SlideInLeft,
        SlideInRight;

        /* renamed from: values, reason: to resolve conflict with enum method */
        public static EnumC3227a[] valuesCustom() {
            EnumC3227a[] valuesCustom = values();
            return (EnumC3227a[]) Arrays.copyOf(valuesCustom, valuesCustom.length);
        }
    }

    /* renamed from: com.chad.library.adapter.base.BaseQuickAdapter$c */
    public static final class C3229c extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ VH f8877c;

        /* renamed from: e */
        public final /* synthetic */ BaseQuickAdapter<T, VH> f8878e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3229c(VH vh, BaseQuickAdapter<T, VH> baseQuickAdapter) {
            super(1);
            this.f8877c = vh;
            this.f8878e = baseQuickAdapter;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(View view) {
            View v = view;
            Intrinsics.checkNotNullParameter(v, "v");
            int adapterPosition = this.f8877c.getAdapterPosition();
            if (adapterPosition != -1) {
                this.f8878e.setOnItemClick(v, adapterPosition - this.f8878e.getHeaderLayoutCount());
            }
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.chad.library.adapter.base.BaseQuickAdapter$d */
    public static final class C3230d extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ VH f8879c;

        /* renamed from: e */
        public final /* synthetic */ BaseQuickAdapter<T, VH> f8880e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3230d(VH vh, BaseQuickAdapter<T, VH> baseQuickAdapter) {
            super(1);
            this.f8879c = vh;
            this.f8880e = baseQuickAdapter;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(View view) {
            View v = view;
            Intrinsics.checkNotNullParameter(v, "v");
            int adapterPosition = this.f8879c.getAdapterPosition();
            if (adapterPosition != -1) {
                this.f8880e.setOnItemChildClick(v, adapterPosition - this.f8880e.getHeaderLayoutCount());
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @JvmOverloads
    public BaseQuickAdapter(@LayoutRes int i2) {
        this(i2, null, 2, 0 == true ? 1 : 0);
    }

    public /* synthetic */ BaseQuickAdapter(int i2, List list, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(i2, (i3 & 2) != 0 ? null : list);
    }

    private final void addAnimation(RecyclerView.ViewHolder holder) {
        if (this.animationEnable) {
            if (!this.isAnimationFirstOnly || holder.getLayoutPosition() > this.mLastPosition) {
                InterfaceC1286b interfaceC1286b = this.adapterAnimation;
                if (interfaceC1286b == null) {
                    interfaceC1286b = null;
                }
                if (interfaceC1286b == null) {
                    interfaceC1286b = new C1285a(0.0f, 1);
                }
                View view = holder.itemView;
                Intrinsics.checkNotNullExpressionValue(view, "holder.itemView");
                for (Animator animator : interfaceC1286b.mo307a(view)) {
                    startAnim(animator, holder.getLayoutPosition());
                }
                this.mLastPosition = holder.getLayoutPosition();
            }
        }
    }

    public static /* synthetic */ int addFooterView$default(BaseQuickAdapter baseQuickAdapter, View view, int i2, int i3, int i4, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: addFooterView");
        }
        if ((i4 & 2) != 0) {
            i2 = -1;
        }
        if ((i4 & 4) != 0) {
            i3 = 1;
        }
        return baseQuickAdapter.addFooterView(view, i2, i3);
    }

    public static /* synthetic */ int addHeaderView$default(BaseQuickAdapter baseQuickAdapter, View view, int i2, int i3, int i4, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: addHeaderView");
        }
        if ((i4 & 2) != 0) {
            i2 = -1;
        }
        if ((i4 & 4) != 0) {
            i3 = 1;
        }
        return baseQuickAdapter.addHeaderView(view, i2, i3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindViewClickListener$lambda-4$lambda-3, reason: not valid java name */
    public static final boolean m5733bindViewClickListener$lambda4$lambda3(BaseViewHolder viewHolder, BaseQuickAdapter this$0, View v) {
        Intrinsics.checkNotNullParameter(viewHolder, "$viewHolder");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        int adapterPosition = viewHolder.getAdapterPosition();
        if (adapterPosition == -1) {
            return false;
        }
        int headerLayoutCount = adapterPosition - this$0.getHeaderLayoutCount();
        Intrinsics.checkNotNullExpressionValue(v, "v");
        return this$0.setOnItemLongClick(v, headerLayoutCount);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindViewClickListener$lambda-9$lambda-8$lambda-7, reason: not valid java name */
    public static final boolean m5734bindViewClickListener$lambda9$lambda8$lambda7(BaseViewHolder viewHolder, BaseQuickAdapter this$0, View v) {
        Intrinsics.checkNotNullParameter(viewHolder, "$viewHolder");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        int adapterPosition = viewHolder.getAdapterPosition();
        if (adapterPosition == -1) {
            return false;
        }
        int headerLayoutCount = adapterPosition - this$0.getHeaderLayoutCount();
        Intrinsics.checkNotNullExpressionValue(v, "v");
        return this$0.setOnItemChildLongClick(v, headerLayoutCount);
    }

    private final void checkModule() {
        if (this instanceof InterfaceC1320h) {
            this.loadMoreModule = addLoadMoreModule(this);
        }
    }

    private final VH createBaseGenericKInstance(Class<?> z, View view) {
        try {
            if (!z.isMemberClass() || Modifier.isStatic(z.getModifiers())) {
                Constructor<?> declaredConstructor = z.getDeclaredConstructor(View.class);
                Intrinsics.checkNotNullExpressionValue(declaredConstructor, "z.getDeclaredConstructor(View::class.java)");
                declaredConstructor.setAccessible(true);
                Object newInstance = declaredConstructor.newInstance(view);
                if (newInstance != null) {
                    return (VH) newInstance;
                }
                throw new NullPointerException("null cannot be cast to non-null type VH of com.chad.library.adapter.base.BaseQuickAdapter");
            }
            Constructor<?> declaredConstructor2 = z.getDeclaredConstructor(getClass(), View.class);
            Intrinsics.checkNotNullExpressionValue(declaredConstructor2, "z.getDeclaredConstructor(javaClass, View::class.java)");
            declaredConstructor2.setAccessible(true);
            Object newInstance2 = declaredConstructor2.newInstance(this, view);
            if (newInstance2 != null) {
                return (VH) newInstance2;
            }
            throw new NullPointerException("null cannot be cast to non-null type VH of com.chad.library.adapter.base.BaseQuickAdapter");
        } catch (IllegalAccessException e2) {
            e2.printStackTrace();
            return null;
        } catch (InstantiationException e3) {
            e3.printStackTrace();
            return null;
        } catch (NoSuchMethodException e4) {
            e4.printStackTrace();
            return null;
        } catch (InvocationTargetException e5) {
            e5.printStackTrace();
            return null;
        }
    }

    private final Class<?> getInstancedGenericKClass(Class<?> z) {
        try {
            Type genericSuperclass = z.getGenericSuperclass();
            if (!(genericSuperclass instanceof ParameterizedType)) {
                return null;
            }
            Type[] types = ((ParameterizedType) genericSuperclass).getActualTypeArguments();
            Intrinsics.checkNotNullExpressionValue(types, "types");
            int i2 = 0;
            int length = types.length;
            while (i2 < length) {
                Type type = types[i2];
                i2++;
                if (type instanceof Class) {
                    if (BaseViewHolder.class.isAssignableFrom((Class) type)) {
                        return (Class) type;
                    }
                } else if (type instanceof ParameterizedType) {
                    Type rawType = ((ParameterizedType) type).getRawType();
                    if ((rawType instanceof Class) && BaseViewHolder.class.isAssignableFrom((Class) rawType)) {
                        return (Class) rawType;
                    }
                } else {
                    continue;
                }
            }
            return null;
        } catch (TypeNotPresentException e2) {
            e2.printStackTrace();
            return null;
        } catch (GenericSignatureFormatError e3) {
            e3.printStackTrace();
            return null;
        } catch (MalformedParameterizedTypeException e4) {
            e4.printStackTrace();
            return null;
        }
    }

    public static /* synthetic */ int setFooterView$default(BaseQuickAdapter baseQuickAdapter, View view, int i2, int i3, int i4, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: setFooterView");
        }
        if ((i4 & 2) != 0) {
            i2 = 0;
        }
        if ((i4 & 4) != 0) {
            i3 = 1;
        }
        return baseQuickAdapter.setFooterView(view, i2, i3);
    }

    public static /* synthetic */ int setHeaderView$default(BaseQuickAdapter baseQuickAdapter, View view, int i2, int i3, int i4, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: setHeaderView");
        }
        if ((i4 & 2) != 0) {
            i2 = 0;
        }
        if ((i4 & 4) != 0) {
            i3 = 1;
        }
        return baseQuickAdapter.setHeaderView(view, i2, i3);
    }

    public final void addChildClickViewIds(@IdRes @NotNull int... viewIds) {
        Intrinsics.checkNotNullParameter(viewIds, "viewIds");
        int length = viewIds.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = viewIds[i2];
            i2++;
            this.childClickViewIds.add(Integer.valueOf(i3));
        }
    }

    public final void addChildLongClickViewIds(@IdRes @NotNull int... viewIds) {
        Intrinsics.checkNotNullParameter(viewIds, "viewIds");
        int length = viewIds.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = viewIds[i2];
            i2++;
            this.childLongClickViewIds.add(Integer.valueOf(i3));
        }
    }

    public void addData(@IntRange(from = 0) int position, T data) {
        this.data.add(position, data);
        notifyItemInserted(getHeaderLayoutCount() + position);
        compatibilityDataSizeChanged(1);
    }

    @NotNull
    public C1316d addDraggableModule(@NotNull BaseQuickAdapter<?, ?> baseQuickAdapter) {
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(baseQuickAdapter, "baseQuickAdapter");
        return new C1316d(baseQuickAdapter);
    }

    @JvmOverloads
    public final int addFooterView(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        return addFooterView$default(this, view, 0, 0, 6, null);
    }

    @JvmOverloads
    public final int addFooterView(@NotNull View view, int i2) {
        Intrinsics.checkNotNullParameter(view, "view");
        return addFooterView$default(this, view, i2, 0, 4, null);
    }

    @JvmOverloads
    public final int addFooterView(@NotNull View view, int index, int orientation) {
        int footerViewPosition;
        Intrinsics.checkNotNullParameter(view, "view");
        if (this.mFooterLayout == null) {
            LinearLayout linearLayout = new LinearLayout(view.getContext());
            this.mFooterLayout = linearLayout;
            linearLayout.setOrientation(orientation);
            LinearLayout linearLayout2 = this.mFooterLayout;
            if (linearLayout2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            }
            linearLayout2.setLayoutParams(orientation == 1 ? new RecyclerView.LayoutParams(-1, -2) : new RecyclerView.LayoutParams(-2, -1));
        }
        LinearLayout linearLayout3 = this.mFooterLayout;
        if (linearLayout3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
            throw null;
        }
        int childCount = linearLayout3.getChildCount();
        if (index < 0 || index > childCount) {
            index = childCount;
        }
        LinearLayout linearLayout4 = this.mFooterLayout;
        if (linearLayout4 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
            throw null;
        }
        linearLayout4.addView(view, index);
        LinearLayout linearLayout5 = this.mFooterLayout;
        if (linearLayout5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
            throw null;
        }
        if (linearLayout5.getChildCount() == 1 && (footerViewPosition = getFooterViewPosition()) != -1) {
            notifyItemInserted(footerViewPosition);
        }
        return index;
    }

    @JvmOverloads
    public final int addHeaderView(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        return addHeaderView$default(this, view, 0, 0, 6, null);
    }

    @JvmOverloads
    public final int addHeaderView(@NotNull View view, int i2) {
        Intrinsics.checkNotNullParameter(view, "view");
        return addHeaderView$default(this, view, i2, 0, 4, null);
    }

    @JvmOverloads
    public final int addHeaderView(@NotNull View view, int index, int orientation) {
        int headerViewPosition;
        Intrinsics.checkNotNullParameter(view, "view");
        if (this.mHeaderLayout == null) {
            LinearLayout linearLayout = new LinearLayout(view.getContext());
            this.mHeaderLayout = linearLayout;
            linearLayout.setOrientation(orientation);
            LinearLayout linearLayout2 = this.mHeaderLayout;
            if (linearLayout2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            }
            linearLayout2.setLayoutParams(orientation == 1 ? new RecyclerView.LayoutParams(-1, -2) : new RecyclerView.LayoutParams(-2, -1));
        }
        LinearLayout linearLayout3 = this.mHeaderLayout;
        if (linearLayout3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
            throw null;
        }
        int childCount = linearLayout3.getChildCount();
        if (index < 0 || index > childCount) {
            index = childCount;
        }
        LinearLayout linearLayout4 = this.mHeaderLayout;
        if (linearLayout4 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
            throw null;
        }
        linearLayout4.addView(view, index);
        LinearLayout linearLayout5 = this.mHeaderLayout;
        if (linearLayout5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
            throw null;
        }
        if (linearLayout5.getChildCount() == 1 && (headerViewPosition = getHeaderViewPosition()) != -1) {
            notifyItemInserted(headerViewPosition);
        }
        return index;
    }

    @NotNull
    public C1318f addLoadMoreModule(@NotNull BaseQuickAdapter<?, ?> baseQuickAdapter) {
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(baseQuickAdapter, "baseQuickAdapter");
        return new C1318f(baseQuickAdapter);
    }

    @NotNull
    public C1319g addUpFetchModule(@NotNull BaseQuickAdapter<?, ?> baseQuickAdapter) {
        Intrinsics.checkNotNullParameter(this, "this");
        Intrinsics.checkNotNullParameter(baseQuickAdapter, "baseQuickAdapter");
        return new C1319g(baseQuickAdapter);
    }

    public void bindViewClickListener(@NotNull final VH viewHolder, int viewType) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        if (this.mOnItemClickListener != null) {
            C4195m.m4779M(viewHolder.itemView, 0L, new C3229c(viewHolder, this), 1);
        }
        if (this.mOnItemLongClickListener != null) {
            viewHolder.itemView.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.b.a.a.a.e
                @Override // android.view.View.OnLongClickListener
                public final boolean onLongClick(View view) {
                    boolean m5733bindViewClickListener$lambda4$lambda3;
                    m5733bindViewClickListener$lambda4$lambda3 = BaseQuickAdapter.m5733bindViewClickListener$lambda4$lambda3(BaseViewHolder.this, this, view);
                    return m5733bindViewClickListener$lambda4$lambda3;
                }
            });
        }
        if (this.mOnItemChildClickListener != null) {
            Iterator<Integer> it = getChildClickViewIds().iterator();
            while (it.hasNext()) {
                Integer id = it.next();
                View view = viewHolder.itemView;
                Intrinsics.checkNotNullExpressionValue(id, "id");
                View findViewById = view.findViewById(id.intValue());
                if (findViewById != null) {
                    if (!findViewById.isClickable()) {
                        findViewById.setClickable(true);
                    }
                    C4195m.m4779M(findViewById, 0L, new C3230d(viewHolder, this), 1);
                }
            }
        }
        if (this.mOnItemChildLongClickListener == null) {
            return;
        }
        Iterator<Integer> it2 = getChildLongClickViewIds().iterator();
        while (it2.hasNext()) {
            Integer id2 = it2.next();
            View view2 = viewHolder.itemView;
            Intrinsics.checkNotNullExpressionValue(id2, "id");
            View findViewById2 = view2.findViewById(id2.intValue());
            if (findViewById2 != null) {
                if (!findViewById2.isLongClickable()) {
                    findViewById2.setLongClickable(true);
                }
                findViewById2.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.b.a.a.a.d
                    @Override // android.view.View.OnLongClickListener
                    public final boolean onLongClick(View view3) {
                        boolean m5734bindViewClickListener$lambda9$lambda8$lambda7;
                        m5734bindViewClickListener$lambda9$lambda8$lambda7 = BaseQuickAdapter.m5734bindViewClickListener$lambda9$lambda8$lambda7(BaseViewHolder.this, this, view3);
                        return m5734bindViewClickListener$lambda9$lambda8$lambda7;
                    }
                });
            }
        }
    }

    public final void compatibilityDataSizeChanged(int size) {
        if (this.data.size() == size) {
            notifyDataSetChanged();
        }
    }

    public abstract void convert(@NotNull VH helper, T item);

    public void convert(@NotNull VH helper, T item, @NotNull List<? extends Object> payloads) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
    }

    @NotNull
    public VH createBaseViewHolder(@NotNull ViewGroup parent, @LayoutRes int layoutResId) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        return createBaseViewHolder(C4195m.m4803e0(parent, layoutResId));
    }

    @Nullable
    public final InterfaceC1286b getAdapterAnimation() {
        return this.adapterAnimation;
    }

    public final boolean getAnimationEnable() {
        return this.animationEnable;
    }

    @NotNull
    public final LinkedHashSet<Integer> getChildClickViewIds() {
        return this.childClickViewIds;
    }

    @NotNull
    public final LinkedHashSet<Integer> getChildLongClickViewIds() {
        return this.childLongClickViewIds;
    }

    @NotNull
    public final Context getContext() {
        Context context = this.context;
        if (context != null) {
            return context;
        }
        Intrinsics.throwUninitializedPropertyAccessException("context");
        throw null;
    }

    @NotNull
    public final List<T> getData() {
        return this.data;
    }

    public int getDefItemCount() {
        return this.data.size();
    }

    public int getDefItemViewType(int position) {
        return super.getItemViewType(position);
    }

    @NotNull
    public final C1293c<T> getDiffHelper() {
        C1293c<T> c1293c = this.mDiffHelper;
        if (c1293c == null) {
            throw new IllegalStateException("Please use setDiffCallback() or setDiffConfig() first!".toString());
        }
        Intrinsics.checkNotNull(c1293c);
        return c1293c;
    }

    @Nullable
    public final C1316d getDraggableModule() {
        return this.draggableModule;
    }

    @Nullable
    public final FrameLayout getEmptyLayout() {
        FrameLayout frameLayout = this.mEmptyLayout;
        if (frameLayout == null) {
            return null;
        }
        if (frameLayout != null) {
            return frameLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
        throw null;
    }

    @Nullable
    public final LinearLayout getFooterLayout() {
        LinearLayout linearLayout = this.mFooterLayout;
        if (linearLayout == null) {
            return null;
        }
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
        throw null;
    }

    public final int getFooterLayoutCount() {
        return hasFooterLayout() ? 1 : 0;
    }

    public final boolean getFooterViewAsFlow() {
        return this.footerViewAsFlow;
    }

    public final int getFooterViewPosition() {
        if (!hasEmptyView()) {
            return this.data.size() + getHeaderLayoutCount();
        }
        int i2 = 1;
        if (this.headerWithEmptyEnable && hasHeaderLayout()) {
            i2 = 2;
        }
        if (this.footerWithEmptyEnable) {
            return i2;
        }
        return -1;
    }

    public final boolean getFooterWithEmptyEnable() {
        return this.footerWithEmptyEnable;
    }

    @Nullable
    public final LinearLayout getHeaderLayout() {
        LinearLayout linearLayout = this.mHeaderLayout;
        if (linearLayout == null) {
            return null;
        }
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
        throw null;
    }

    public final int getHeaderLayoutCount() {
        return hasHeaderLayout() ? 1 : 0;
    }

    public final boolean getHeaderViewAsFlow() {
        return this.headerViewAsFlow;
    }

    public final int getHeaderViewPosition() {
        return (!hasEmptyView() || this.headerWithEmptyEnable) ? 0 : -1;
    }

    public final boolean getHeaderWithEmptyEnable() {
        return this.headerWithEmptyEnable;
    }

    public T getItem(@IntRange(from = 0) int position) {
        return this.data.get(position);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        if (hasEmptyView()) {
            int i2 = (this.headerWithEmptyEnable && hasHeaderLayout()) ? 2 : 1;
            return (this.footerWithEmptyEnable && hasFooterLayout()) ? i2 + 1 : i2;
        }
        C1318f c1318f = this.loadMoreModule;
        return getFooterLayoutCount() + getDefItemCount() + getHeaderLayoutCount() + (Intrinsics.areEqual(c1318f == null ? null : Boolean.valueOf(c1318f.m328d()), Boolean.TRUE) ? 1 : 0);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int position) {
        return position;
    }

    @Nullable
    public T getItemOrNull(@IntRange(from = 0) int position) {
        return (T) CollectionsKt___CollectionsKt.getOrNull(this.data, position);
    }

    public int getItemPosition(@Nullable T item) {
        if (item == null || !(!this.data.isEmpty())) {
            return -1;
        }
        return this.data.indexOf(item);
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [boolean] */
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        if (hasEmptyView()) {
            boolean z = this.headerWithEmptyEnable && hasHeaderLayout();
            if (position != 0) {
                return position != 1 ? FOOTER_VIEW : FOOTER_VIEW;
            }
            if (z) {
                return HEADER_VIEW;
            }
            return EMPTY_VIEW;
        }
        boolean hasHeaderLayout = hasHeaderLayout();
        if (hasHeaderLayout && position == 0) {
            return HEADER_VIEW;
        }
        if (hasHeaderLayout) {
            position--;
        }
        int size = this.data.size();
        return position < size ? getDefItemViewType(position) : position - size < hasFooterLayout() ? FOOTER_VIEW : LOAD_MORE_VIEW;
    }

    @Nullable
    public final C1318f getLoadMoreModule() {
        return this.loadMoreModule;
    }

    @Nullable
    /* renamed from: getOnItemChildClickListener, reason: from getter */
    public final InterfaceC1302b getMOnItemChildClickListener() {
        return this.mOnItemChildClickListener;
    }

    @Nullable
    /* renamed from: getOnItemChildLongClickListener, reason: from getter */
    public final InterfaceC1303c getMOnItemChildLongClickListener() {
        return this.mOnItemChildLongClickListener;
    }

    @Nullable
    /* renamed from: getOnItemClickListener, reason: from getter */
    public final InterfaceC1304d getMOnItemClickListener() {
        return this.mOnItemClickListener;
    }

    @Nullable
    /* renamed from: getOnItemLongClickListener, reason: from getter */
    public final InterfaceC1306f getMOnItemLongClickListener() {
        return this.mOnItemLongClickListener;
    }

    @Nullable
    public final C1319g getUpFetchModule() {
        return this.upFetchModule;
    }

    @Nullable
    public final View getViewByPosition(int position, @IdRes int viewId) {
        BaseViewHolder baseViewHolder;
        RecyclerView recyclerView = getWeakRecyclerView().get();
        if (recyclerView == null || (baseViewHolder = (BaseViewHolder) recyclerView.findViewHolderForLayoutPosition(position)) == null) {
            return null;
        }
        return baseViewHolder.m3913c(viewId);
    }

    @NotNull
    public final WeakReference<RecyclerView> getWeakRecyclerView() {
        WeakReference<RecyclerView> weakReference = this.weakRecyclerView;
        if (weakReference != null) {
            return weakReference;
        }
        Intrinsics.throwUninitializedPropertyAccessException("weakRecyclerView");
        throw null;
    }

    public final boolean hasEmptyView() {
        FrameLayout frameLayout = this.mEmptyLayout;
        if (frameLayout != null) {
            if (frameLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                throw null;
            }
            if (frameLayout.getChildCount() != 0 && this.isUseEmpty) {
                return this.data.isEmpty();
            }
            return false;
        }
        return false;
    }

    public final boolean hasFooterLayout() {
        LinearLayout linearLayout = this.mFooterLayout;
        if (linearLayout == null) {
            return false;
        }
        if (linearLayout != null) {
            return linearLayout.getChildCount() > 0;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
        throw null;
    }

    public final boolean hasHeaderLayout() {
        LinearLayout linearLayout = this.mHeaderLayout;
        if (linearLayout == null) {
            return false;
        }
        if (linearLayout != null) {
            return linearLayout.getChildCount() > 0;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
        throw null;
    }

    /* renamed from: isAnimationFirstOnly, reason: from getter */
    public final boolean getIsAnimationFirstOnly() {
        return this.isAnimationFirstOnly;
    }

    public boolean isFixedViewType(int type) {
        return type == 268436821 || type == 268435729 || type == 268436275 || type == 268436002;
    }

    /* renamed from: isUseEmpty, reason: from getter */
    public final boolean getIsUseEmpty() {
        return this.isUseEmpty;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onAttachedToRecyclerView(@NotNull RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        super.onAttachedToRecyclerView(recyclerView);
        setWeakRecyclerView(new WeakReference<>(recyclerView));
        Context context = recyclerView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "recyclerView.context");
        this.context = context;
        C1316d c1316d = this.draggableModule;
        if (c1316d != null) {
            Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
            ItemTouchHelper itemTouchHelper = c1316d.f1044b;
            if (itemTouchHelper == null) {
                Intrinsics.throwUninitializedPropertyAccessException("itemTouchHelper");
                throw null;
            }
            itemTouchHelper.attachToRecyclerView(recyclerView);
        }
        final RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
        if (layoutManager instanceof GridLayoutManager) {
            GridLayoutManager gridLayoutManager = (GridLayoutManager) layoutManager;
            final GridLayoutManager.SpanSizeLookup spanSizeLookup = gridLayoutManager.getSpanSizeLookup();
            gridLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup(this) { // from class: com.chad.library.adapter.base.BaseQuickAdapter$onAttachedToRecyclerView$1

                /* renamed from: a */
                public final /* synthetic */ BaseQuickAdapter<T, VH> f8881a;

                {
                    this.f8881a = this;
                }

                @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
                public int getSpanSize(int position) {
                    InterfaceC1301a interfaceC1301a;
                    InterfaceC1301a interfaceC1301a2;
                    int itemViewType = this.f8881a.getItemViewType(position);
                    if (itemViewType == 268435729 && this.f8881a.getHeaderViewAsFlow()) {
                        return 1;
                    }
                    if (itemViewType == 268436275 && this.f8881a.getFooterViewAsFlow()) {
                        return 1;
                    }
                    interfaceC1301a = ((BaseQuickAdapter) this.f8881a).mSpanSizeLookup;
                    if (interfaceC1301a == null) {
                        return this.f8881a.isFixedViewType(itemViewType) ? ((GridLayoutManager) layoutManager).getSpanCount() : spanSizeLookup.getSpanSize(position);
                    }
                    if (this.f8881a.isFixedViewType(itemViewType)) {
                        return ((GridLayoutManager) layoutManager).getSpanCount();
                    }
                    interfaceC1301a2 = ((BaseQuickAdapter) this.f8881a).mSpanSizeLookup;
                    Intrinsics.checkNotNull(interfaceC1301a2);
                    return interfaceC1301a2.m311a((GridLayoutManager) layoutManager, itemViewType, position - this.f8881a.getHeaderLayoutCount());
                }
            });
        }
    }

    @NotNull
    public VH onCreateDefViewHolder(@NotNull ViewGroup parent, int viewType) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        return createBaseViewHolder(parent, this.layoutResId);
    }

    public void onItemViewHolderCreated(@NotNull VH viewHolder, int viewType) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
    }

    public void remove(@IntRange(from = 0) int position) {
        if (position >= this.data.size()) {
            return;
        }
        this.data.remove(position);
        int headerLayoutCount = getHeaderLayoutCount() + position;
        notifyItemRemoved(headerLayoutCount);
        compatibilityDataSizeChanged(0);
        notifyItemRangeChanged(headerLayoutCount, this.data.size() - headerLayoutCount);
    }

    public final void removeAllFooterView() {
        if (hasFooterLayout()) {
            LinearLayout linearLayout = this.mFooterLayout;
            if (linearLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            }
            linearLayout.removeAllViews();
            int footerViewPosition = getFooterViewPosition();
            if (footerViewPosition != -1) {
                notifyItemRemoved(footerViewPosition);
            }
        }
    }

    public final void removeAllHeaderView() {
        if (hasHeaderLayout()) {
            LinearLayout linearLayout = this.mHeaderLayout;
            if (linearLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            }
            linearLayout.removeAllViews();
            int headerViewPosition = getHeaderViewPosition();
            if (headerViewPosition != -1) {
                notifyItemRemoved(headerViewPosition);
            }
        }
    }

    public final void removeEmptyView() {
        FrameLayout frameLayout = this.mEmptyLayout;
        if (frameLayout != null) {
            if (frameLayout != null) {
                frameLayout.removeAllViews();
            } else {
                Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                throw null;
            }
        }
    }

    public final void removeFooterView(@NotNull View footer) {
        int footerViewPosition;
        Intrinsics.checkNotNullParameter(footer, "footer");
        if (hasFooterLayout()) {
            LinearLayout linearLayout = this.mFooterLayout;
            if (linearLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            }
            linearLayout.removeView(footer);
            LinearLayout linearLayout2 = this.mFooterLayout;
            if (linearLayout2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            }
            if (linearLayout2.getChildCount() != 0 || (footerViewPosition = getFooterViewPosition()) == -1) {
                return;
            }
            notifyItemRemoved(footerViewPosition);
        }
    }

    public final void removeHeaderView(@NotNull View header) {
        int headerViewPosition;
        Intrinsics.checkNotNullParameter(header, "header");
        if (hasHeaderLayout()) {
            LinearLayout linearLayout = this.mHeaderLayout;
            if (linearLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            }
            linearLayout.removeView(header);
            LinearLayout linearLayout2 = this.mHeaderLayout;
            if (linearLayout2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            }
            if (linearLayout2.getChildCount() != 0 || (headerViewPosition = getHeaderViewPosition()) == -1) {
                return;
            }
            notifyItemRemoved(headerViewPosition);
        }
    }

    public void replaceData(@NotNull Collection<? extends T> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        if (!Intrinsics.areEqual(newData, this.data)) {
            this.data.clear();
            this.data.addAll(newData);
        }
        notifyDataSetChanged();
    }

    public final void setAdapterAnimation(@Nullable InterfaceC1286b interfaceC1286b) {
        this.animationEnable = true;
        this.adapterAnimation = interfaceC1286b;
    }

    public final void setAnimationEnable(boolean z) {
        this.animationEnable = z;
    }

    public final void setAnimationFirstOnly(boolean z) {
        this.isAnimationFirstOnly = z;
    }

    public final void setAnimationWithDefault(@NotNull EnumC3227a animationType) {
        InterfaceC1286b c1285a;
        Intrinsics.checkNotNullParameter(animationType, "animationType");
        int ordinal = animationType.ordinal();
        if (ordinal == 0) {
            c1285a = new C1285a(0.0f, 1);
        } else if (ordinal == 1) {
            c1285a = new C1287c(0.0f, 1);
        } else if (ordinal == 2) {
            c1285a = new C1288d();
        } else if (ordinal == 3) {
            c1285a = new C1289e();
        } else {
            if (ordinal != 4) {
                throw new NoWhenBranchMatchedException();
            }
            c1285a = new C1290f();
        }
        setAdapterAnimation(c1285a);
    }

    public void setData(@IntRange(from = 0) int index, T data) {
        if (index >= this.data.size()) {
            return;
        }
        this.data.set(index, data);
        notifyItemChanged(getHeaderLayoutCount() + index);
    }

    public final void setData$com_github_CymChad_brvah(@NotNull List<T> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.data = list;
    }

    public final void setDiffCallback(@NotNull DiffUtil.ItemCallback<T> diffCallback) {
        Intrinsics.checkNotNullParameter(diffCallback, "diffCallback");
        C1294d.a aVar = new C1294d.a(diffCallback);
        if (aVar.f1031d == null) {
            synchronized (C1294d.a.f1028a) {
                if (C1294d.a.f1029b == null) {
                    C1294d.a.f1029b = Executors.newFixedThreadPool(2);
                }
                Unit unit = Unit.INSTANCE;
            }
            aVar.f1031d = C1294d.a.f1029b;
        }
        Executor executor = aVar.f1031d;
        Intrinsics.checkNotNull(executor);
        setDiffConfig(new C1294d<>(null, executor, aVar.f1030c));
    }

    public final void setDiffConfig(@NotNull C1294d<T> config) {
        Intrinsics.checkNotNullParameter(config, "config");
        this.mDiffHelper = new C1293c<>(this, config);
    }

    public void setDiffNewData(@Nullable final List<T> newData) {
        if (hasEmptyView()) {
            setNewData(newData);
            return;
        }
        final C1293c<T> c1293c = this.mDiffHelper;
        if (c1293c == null) {
            return;
        }
        final Runnable runnable = null;
        final int i2 = c1293c.f1023g + 1;
        c1293c.f1023g = i2;
        if (Intrinsics.areEqual(newData, c1293c.f1017a.getData())) {
            return;
        }
        final List<? extends T> data = c1293c.f1017a.getData();
        if (newData == null) {
            int size = c1293c.f1017a.getData().size();
            c1293c.f1017a.setData$com_github_CymChad_brvah(new ArrayList());
            c1293c.f1019c.onRemoved(0, size);
            c1293c.m308a(data, null);
            return;
        }
        if (!c1293c.f1017a.getData().isEmpty()) {
            c1293c.f1018b.f1026b.execute(new Runnable() { // from class: b.b.a.a.a.i.b
                @Override // java.lang.Runnable
                public final void run() {
                    final C1293c this$0 = C1293c.this;
                    final List oldList = data;
                    final List list = newData;
                    final int i3 = i2;
                    final Runnable runnable2 = runnable;
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(oldList, "$oldList");
                    final DiffUtil.DiffResult calculateDiff = DiffUtil.calculateDiff(new DiffUtil.Callback() { // from class: com.chad.library.adapter.base.diff.BrvahAsyncDiffer$submitList$1$result$1
                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public boolean areContentsTheSame(int oldItemPosition, int newItemPosition) {
                            Object obj = oldList.get(oldItemPosition);
                            Object obj2 = list.get(newItemPosition);
                            if (obj != null && obj2 != null) {
                                return this$0.f1018b.f1027c.areContentsTheSame(obj, obj2);
                            }
                            if (obj == null && obj2 == null) {
                                return true;
                            }
                            throw new AssertionError();
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public boolean areItemsTheSame(int oldItemPosition, int newItemPosition) {
                            Object obj = oldList.get(oldItemPosition);
                            Object obj2 = list.get(newItemPosition);
                            return (obj == null || obj2 == null) ? obj == null && obj2 == null : this$0.f1018b.f1027c.areItemsTheSame(obj, obj2);
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        @Nullable
                        public Object getChangePayload(int oldItemPosition, int newItemPosition) {
                            Object obj = oldList.get(oldItemPosition);
                            Object obj2 = list.get(newItemPosition);
                            if (obj == null || obj2 == null) {
                                throw new AssertionError();
                            }
                            return this$0.f1018b.f1027c.getChangePayload(obj, obj2);
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public int getNewListSize() {
                            return list.size();
                        }

                        @Override // androidx.recyclerview.widget.DiffUtil.Callback
                        public int getOldListSize() {
                            return oldList.size();
                        }
                    });
                    Intrinsics.checkNotNullExpressionValue(calculateDiff, "@JvmOverloads\n    fun submitList(newList: MutableList<T>?, commitCallback: Runnable? = null) {\n        // incrementing generation means any currently-running diffs are discarded when they finish\n        val runGeneration: Int = ++mMaxScheduledGeneration\n        if (newList == adapter.data) {\n            // nothing to do (Note - still had to inc generation, since may have ongoing work)\n            commitCallback?.run()\n            return\n        }\n        val oldList: List<T> = adapter.data\n        // fast simple remove all\n        if (newList == null) {\n            val countRemoved: Int = adapter.data.size\n            adapter.data = arrayListOf()\n            // notify last, after list is updated\n            mUpdateCallback.onRemoved(0, countRemoved)\n            onCurrentListChanged(oldList, commitCallback)\n            return\n        }\n        // fast simple first insert\n        if (adapter.data.isEmpty()) {\n            adapter.data = newList\n            // notify last, after list is updated\n            mUpdateCallback.onInserted(0, newList.size)\n            onCurrentListChanged(oldList, commitCallback)\n            return\n        }\n\n        config.backgroundThreadExecutor.execute {\n            val result = DiffUtil.calculateDiff(object : DiffUtil.Callback() {\n                override fun getOldListSize(): Int {\n                    return oldList.size\n                }\n\n                override fun getNewListSize(): Int {\n                    return newList.size\n                }\n\n                override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {\n                    val oldItem: T? = oldList[oldItemPosition]\n                    val newItem: T? = newList[newItemPosition]\n                    return if (oldItem != null && newItem != null) {\n                        config.diffCallback.areItemsTheSame(oldItem, newItem)\n                    } else oldItem == null && newItem == null\n                    // If both items are null we consider them the same.\n                }\n\n                override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {\n                    val oldItem: T? = oldList[oldItemPosition]\n                    val newItem: T? = newList[newItemPosition]\n                    if (oldItem != null && newItem != null) {\n                        return config.diffCallback.areContentsTheSame(oldItem, newItem)\n                    }\n                    if (oldItem == null && newItem == null) {\n                        return true\n                    }\n                    throw AssertionError()\n                }\n\n                override fun getChangePayload(oldItemPosition: Int, newItemPosition: Int): Any? {\n                    val oldItem: T? = oldList[oldItemPosition]\n                    val newItem: T? = newList[newItemPosition]\n                    if (oldItem != null && newItem != null) {\n                        return config.diffCallback.getChangePayload(oldItem, newItem)\n                    }\n                    throw AssertionError()\n                }\n            })\n            mMainThreadExecutor.execute {\n                if (mMaxScheduledGeneration == runGeneration) {\n                    latchList(newList, result, commitCallback)\n                }\n            }\n        }\n    }");
                    this$0.f1020d.execute(new Runnable() { // from class: b.b.a.a.a.i.a
                        @Override // java.lang.Runnable
                        public final void run() {
                            C1293c this$02 = C1293c.this;
                            int i4 = i3;
                            List list2 = list;
                            DiffUtil.DiffResult result = calculateDiff;
                            Runnable runnable3 = runnable2;
                            Intrinsics.checkNotNullParameter(this$02, "this$0");
                            Intrinsics.checkNotNullParameter(result, "$result");
                            if (this$02.f1023g == i4) {
                                List data2 = this$02.f1017a.getData();
                                this$02.f1017a.setData$com_github_CymChad_brvah(list2);
                                result.dispatchUpdatesTo(this$02.f1019c);
                                this$02.m308a(data2, runnable3);
                            }
                        }
                    });
                }
            });
            return;
        }
        c1293c.f1017a.setData$com_github_CymChad_brvah(newData);
        c1293c.f1019c.onInserted(0, newData.size());
        c1293c.m308a(data, null);
    }

    public final void setEmptyView(@NotNull View emptyView) {
        boolean z;
        Intrinsics.checkNotNullParameter(emptyView, "emptyView");
        int itemCount = getItemCount();
        int i2 = 0;
        if (this.mEmptyLayout == null) {
            FrameLayout frameLayout = new FrameLayout(emptyView.getContext());
            this.mEmptyLayout = frameLayout;
            if (frameLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                throw null;
            }
            ViewGroup.LayoutParams layoutParams = emptyView.getLayoutParams();
            ViewGroup.LayoutParams layoutParams2 = layoutParams == null ? null : new ViewGroup.LayoutParams(layoutParams.width, layoutParams.height);
            if (layoutParams2 == null) {
                layoutParams2 = new ViewGroup.LayoutParams(-1, -1);
            }
            frameLayout.setLayoutParams(layoutParams2);
            z = true;
        } else {
            ViewGroup.LayoutParams layoutParams3 = emptyView.getLayoutParams();
            if (layoutParams3 != null) {
                FrameLayout frameLayout2 = this.mEmptyLayout;
                if (frameLayout2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                    throw null;
                }
                ViewGroup.LayoutParams layoutParams4 = frameLayout2.getLayoutParams();
                layoutParams4.width = layoutParams3.width;
                layoutParams4.height = layoutParams3.height;
                FrameLayout frameLayout3 = this.mEmptyLayout;
                if (frameLayout3 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                    throw null;
                }
                frameLayout3.setLayoutParams(layoutParams4);
            }
            z = false;
        }
        FrameLayout frameLayout4 = this.mEmptyLayout;
        if (frameLayout4 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
            throw null;
        }
        frameLayout4.removeAllViews();
        FrameLayout frameLayout5 = this.mEmptyLayout;
        if (frameLayout5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
            throw null;
        }
        frameLayout5.addView(emptyView);
        this.isUseEmpty = true;
        if (z && hasEmptyView()) {
            if (this.headerWithEmptyEnable && hasHeaderLayout()) {
                i2 = 1;
            }
            if (getItemCount() > itemCount) {
                notifyItemInserted(i2);
            } else {
                notifyDataSetChanged();
            }
        }
    }

    @JvmOverloads
    public final int setFooterView(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        return setFooterView$default(this, view, 0, 0, 6, null);
    }

    @JvmOverloads
    public final int setFooterView(@NotNull View view, int i2) {
        Intrinsics.checkNotNullParameter(view, "view");
        return setFooterView$default(this, view, i2, 0, 4, null);
    }

    @JvmOverloads
    public final int setFooterView(@NotNull View view, int index, int orientation) {
        Intrinsics.checkNotNullParameter(view, "view");
        LinearLayout linearLayout = this.mFooterLayout;
        if (linearLayout != null) {
            if (linearLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            }
            if (linearLayout.getChildCount() > index) {
                LinearLayout linearLayout2 = this.mFooterLayout;
                if (linearLayout2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                    throw null;
                }
                linearLayout2.removeViewAt(index);
                LinearLayout linearLayout3 = this.mFooterLayout;
                if (linearLayout3 != null) {
                    linearLayout3.addView(view, index);
                    return index;
                }
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            }
        }
        return addFooterView(view, index, orientation);
    }

    public final void setFooterViewAsFlow(boolean z) {
        this.footerViewAsFlow = z;
    }

    public final void setFooterWithEmptyEnable(boolean z) {
        this.footerWithEmptyEnable = z;
    }

    public void setFullSpan(@NotNull RecyclerView.ViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        ViewGroup.LayoutParams layoutParams = holder.itemView.getLayoutParams();
        if (layoutParams instanceof StaggeredGridLayoutManager.LayoutParams) {
            ((StaggeredGridLayoutManager.LayoutParams) layoutParams).setFullSpan(true);
        }
    }

    public void setGridSpanSizeLookup(@Nullable InterfaceC1301a spanSizeLookup) {
        this.mSpanSizeLookup = spanSizeLookup;
    }

    @JvmOverloads
    public final int setHeaderView(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        return setHeaderView$default(this, view, 0, 0, 6, null);
    }

    @JvmOverloads
    public final int setHeaderView(@NotNull View view, int i2) {
        Intrinsics.checkNotNullParameter(view, "view");
        return setHeaderView$default(this, view, i2, 0, 4, null);
    }

    @JvmOverloads
    public final int setHeaderView(@NotNull View view, int index, int orientation) {
        Intrinsics.checkNotNullParameter(view, "view");
        LinearLayout linearLayout = this.mHeaderLayout;
        if (linearLayout != null) {
            if (linearLayout == null) {
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            }
            if (linearLayout.getChildCount() > index) {
                LinearLayout linearLayout2 = this.mHeaderLayout;
                if (linearLayout2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                    throw null;
                }
                linearLayout2.removeViewAt(index);
                LinearLayout linearLayout3 = this.mHeaderLayout;
                if (linearLayout3 != null) {
                    linearLayout3.addView(view, index);
                    return index;
                }
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            }
        }
        return addHeaderView(view, index, orientation);
    }

    public final void setHeaderViewAsFlow(boolean z) {
        this.headerViewAsFlow = z;
    }

    public final void setHeaderWithEmptyEnable(boolean z) {
        this.headerWithEmptyEnable = z;
    }

    public void setNewData(@Nullable List<T> data) {
        if (Intrinsics.areEqual(data, this.data)) {
            return;
        }
        if (data == null) {
            data = new ArrayList<>();
        }
        this.data = data;
        C1318f c1318f = this.loadMoreModule;
        if (c1318f != null && c1318f.f1053b != null) {
            c1318f.m334k(true);
            c1318f.f1055d = EnumC1311b.Complete;
        }
        this.mLastPosition = -1;
        notifyDataSetChanged();
        C1318f c1318f2 = this.loadMoreModule;
        if (c1318f2 == null) {
            return;
        }
        c1318f2.m326b();
    }

    public void setNewData2(@Nullable List<? extends T> data) {
        if (Intrinsics.areEqual(data, this.data)) {
            return;
        }
        if (data == null) {
            data = new ArrayList<>();
        }
        this.data = TypeIntrinsics.asMutableList(data);
        C1318f c1318f = this.loadMoreModule;
        if (c1318f != null && c1318f.f1053b != null) {
            c1318f.m334k(true);
            c1318f.f1055d = EnumC1311b.Complete;
        }
        this.mLastPosition = -1;
        notifyDataSetChanged();
        C1318f c1318f2 = this.loadMoreModule;
        if (c1318f2 == null) {
            return;
        }
        c1318f2.m326b();
    }

    public void setOnItemChildClick(@NotNull View v, int position) {
        Intrinsics.checkNotNullParameter(v, "v");
        InterfaceC1302b interfaceC1302b = this.mOnItemChildClickListener;
        if (interfaceC1302b == null) {
            return;
        }
        interfaceC1302b.mo215a(this, v, position);
    }

    public void setOnItemChildClickListener(@Nullable InterfaceC1302b listener) {
        this.mOnItemChildClickListener = listener;
    }

    public boolean setOnItemChildLongClick(@NotNull View v, int position) {
        Intrinsics.checkNotNullParameter(v, "v");
        InterfaceC1303c interfaceC1303c = this.mOnItemChildLongClickListener;
        if (interfaceC1303c == null) {
            return false;
        }
        return interfaceC1303c.mo213a(this, v, position);
    }

    public void setOnItemChildLongClickListener(@Nullable InterfaceC1303c listener) {
        this.mOnItemChildLongClickListener = listener;
    }

    public void setOnItemClick(@NotNull View v, int position) {
        Intrinsics.checkNotNullParameter(v, "v");
        InterfaceC1304d interfaceC1304d = this.mOnItemClickListener;
        if (interfaceC1304d == null) {
            return;
        }
        interfaceC1304d.onItemClick(this, v, position);
    }

    public void setOnItemClickListener(@Nullable InterfaceC1304d listener) {
        this.mOnItemClickListener = listener;
    }

    public boolean setOnItemLongClick(@NotNull View v, int position) {
        Intrinsics.checkNotNullParameter(v, "v");
        InterfaceC1306f interfaceC1306f = this.mOnItemLongClickListener;
        if (interfaceC1306f == null) {
            return false;
        }
        return interfaceC1306f.mo214a(this, v, position);
    }

    public void setOnItemLongClickListener(@Nullable InterfaceC1306f listener) {
        this.mOnItemLongClickListener = listener;
    }

    public final void setUseEmpty(boolean z) {
        this.isUseEmpty = z;
    }

    public final void setWeakRecyclerView(@NotNull WeakReference<RecyclerView> weakReference) {
        Intrinsics.checkNotNullParameter(weakReference, "<set-?>");
        this.weakRecyclerView = weakReference;
    }

    public void startAnim(@NotNull Animator anim, int index) {
        Intrinsics.checkNotNullParameter(anim, "anim");
        anim.start();
    }

    @JvmOverloads
    public BaseQuickAdapter(@LayoutRes int i2, @Nullable List<T> list) {
        this.layoutResId = i2;
        this.data = list == null ? new ArrayList<>() : list;
        this.isUseEmpty = true;
        this.isAnimationFirstOnly = true;
        this.mLastPosition = -1;
        checkModule();
        this.childClickViewIds = new LinkedHashSet<>();
        this.childLongClickViewIds = new LinkedHashSet<>();
    }

    @NotNull
    public VH createBaseViewHolder(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        Class<?> cls = null;
        for (Class<?> cls2 = getClass(); cls == null && cls2 != null; cls2 = cls2.getSuperclass()) {
            cls = getInstancedGenericKClass(cls2);
        }
        VH createBaseGenericKInstance = cls == null ? (VH) new BaseViewHolder(view) : createBaseGenericKInstance(cls, view);
        return createBaseGenericKInstance == null ? (VH) new BaseViewHolder(view) : createBaseGenericKInstance;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public /* bridge */ /* synthetic */ void onBindViewHolder(RecyclerView.ViewHolder viewHolder, int i2, List list) {
        onBindViewHolder((BaseQuickAdapter<T, VH>) viewHolder, i2, (List<Object>) list);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    @NotNull
    public VH onCreateViewHolder(@NotNull ViewGroup parent, int viewType) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        switch (viewType) {
            case HEADER_VIEW /* 268435729 */:
                LinearLayout linearLayout = this.mHeaderLayout;
                if (linearLayout == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                    throw null;
                }
                ViewParent parent2 = linearLayout.getParent();
                if (parent2 instanceof ViewGroup) {
                    ViewGroup viewGroup = (ViewGroup) parent2;
                    LinearLayout linearLayout2 = this.mHeaderLayout;
                    if (linearLayout2 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                        throw null;
                    }
                    viewGroup.removeView(linearLayout2);
                }
                LinearLayout linearLayout3 = this.mHeaderLayout;
                if (linearLayout3 != null) {
                    return createBaseViewHolder(linearLayout3);
                }
                Intrinsics.throwUninitializedPropertyAccessException("mHeaderLayout");
                throw null;
            case LOAD_MORE_VIEW /* 268436002 */:
                C1318f c1318f = this.loadMoreModule;
                Intrinsics.checkNotNull(c1318f);
                VH viewHolder = createBaseViewHolder(c1318f.f1057f.mo320f(parent));
                C1318f c1318f2 = this.loadMoreModule;
                Intrinsics.checkNotNull(c1318f2);
                Objects.requireNonNull(c1318f2);
                Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
                C4195m.m4779M(viewHolder.itemView, 0L, new C1317e(c1318f2), 1);
                return viewHolder;
            case FOOTER_VIEW /* 268436275 */:
                LinearLayout linearLayout4 = this.mFooterLayout;
                if (linearLayout4 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                    throw null;
                }
                ViewParent parent3 = linearLayout4.getParent();
                if (parent3 instanceof ViewGroup) {
                    ViewGroup viewGroup2 = (ViewGroup) parent3;
                    LinearLayout linearLayout5 = this.mFooterLayout;
                    if (linearLayout5 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                        throw null;
                    }
                    viewGroup2.removeView(linearLayout5);
                }
                LinearLayout linearLayout6 = this.mFooterLayout;
                if (linearLayout6 != null) {
                    return createBaseViewHolder(linearLayout6);
                }
                Intrinsics.throwUninitializedPropertyAccessException("mFooterLayout");
                throw null;
            case EMPTY_VIEW /* 268436821 */:
                FrameLayout frameLayout = this.mEmptyLayout;
                if (frameLayout == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                    throw null;
                }
                ViewParent parent4 = frameLayout.getParent();
                if (parent4 instanceof ViewGroup) {
                    ViewGroup viewGroup3 = (ViewGroup) parent4;
                    FrameLayout frameLayout2 = this.mEmptyLayout;
                    if (frameLayout2 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                        throw null;
                    }
                    viewGroup3.removeView(frameLayout2);
                }
                FrameLayout frameLayout3 = this.mEmptyLayout;
                if (frameLayout3 != null) {
                    return createBaseViewHolder(frameLayout3);
                }
                Intrinsics.throwUninitializedPropertyAccessException("mEmptyLayout");
                throw null;
            default:
                VH holder = onCreateDefViewHolder(parent, viewType);
                bindViewClickListener(holder, viewType);
                if (this.draggableModule != null) {
                    Intrinsics.checkNotNullParameter(holder, "holder");
                }
                onItemViewHolderCreated(holder, viewType);
                return holder;
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onViewAttachedToWindow(@NotNull VH holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        super.onViewAttachedToWindow((BaseQuickAdapter<T, VH>) holder);
        int itemViewType = holder.getItemViewType();
        if (itemViewType == 268436821 || itemViewType == 268435729 || itemViewType == 268436275 || itemViewType == 268436002) {
            setFullSpan(holder);
        } else {
            addAnimation(holder);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NotNull VH holder, int position) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        C1318f c1318f = this.loadMoreModule;
        if (c1318f != null) {
            c1318f.m325a(position);
        }
        switch (holder.getItemViewType()) {
            case HEADER_VIEW /* 268435729 */:
            case FOOTER_VIEW /* 268436275 */:
            case EMPTY_VIEW /* 268436821 */:
                break;
            case LOAD_MORE_VIEW /* 268436002 */:
                C1318f c1318f2 = this.loadMoreModule;
                if (c1318f2 != null) {
                    c1318f2.f1057f.m315a(holder, c1318f2.f1055d);
                    break;
                }
                break;
            default:
                convert(holder, getItem(position - getHeaderLayoutCount()));
                break;
        }
    }

    public void addData(@NonNull T data) {
        this.data.add(data);
        notifyItemInserted(getHeaderLayoutCount() + this.data.size());
        compatibilityDataSizeChanged(1);
    }

    public void addData(@IntRange(from = 0) int position, @NotNull Collection<? extends T> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        this.data.addAll(position, newData);
        notifyItemRangeInserted(getHeaderLayoutCount() + position, newData.size());
        compatibilityDataSizeChanged(newData.size());
    }

    public void remove(T data) {
        int indexOf = this.data.indexOf(data);
        if (indexOf == -1) {
            return;
        }
        remove(indexOf);
    }

    public void addData(@NonNull @NotNull Collection<? extends T> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        this.data.addAll(newData);
        notifyItemRangeInserted(getHeaderLayoutCount() + (this.data.size() - newData.size()), newData.size());
        compatibilityDataSizeChanged(newData.size());
    }

    public void onBindViewHolder(@NotNull VH holder, int position, @NotNull List<Object> payloads) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        if (payloads.isEmpty()) {
            onBindViewHolder((BaseQuickAdapter<T, VH>) holder, position);
        }
        C1318f c1318f = this.loadMoreModule;
        if (c1318f != null) {
            c1318f.m325a(position);
        }
        switch (holder.getItemViewType()) {
            case HEADER_VIEW /* 268435729 */:
            case FOOTER_VIEW /* 268436275 */:
            case EMPTY_VIEW /* 268436821 */:
                break;
            case LOAD_MORE_VIEW /* 268436002 */:
                C1318f c1318f2 = this.loadMoreModule;
                if (c1318f2 != null) {
                    c1318f2.f1057f.m315a(holder, c1318f2.f1055d);
                    break;
                }
                break;
            default:
                convert(holder, getItem(position - getHeaderLayoutCount()), payloads);
                break;
        }
    }

    public void setDiffNewData(@NonNull @NotNull DiffUtil.DiffResult diffResult, @NotNull List<T> newData) {
        Intrinsics.checkNotNullParameter(diffResult, "diffResult");
        Intrinsics.checkNotNullParameter(newData, "newData");
        if (hasEmptyView()) {
            setNewData(newData);
        } else {
            diffResult.dispatchUpdatesTo(new BrvahListUpdateCallback(this));
            this.data = newData;
        }
    }

    public final void setEmptyView(int layoutResId) {
        RecyclerView recyclerView = getWeakRecyclerView().get();
        if (recyclerView == null) {
            return;
        }
        View view = LayoutInflater.from(recyclerView.getContext()).inflate(layoutResId, (ViewGroup) recyclerView, false);
        Intrinsics.checkNotNullExpressionValue(view, "view");
        setEmptyView(view);
    }
}
