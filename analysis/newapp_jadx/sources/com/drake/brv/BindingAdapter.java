package com.drake.brv;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.IdRes;
import androidx.annotation.IntRange;
import androidx.databinding.DataBindingUtil;
import androidx.databinding.ViewDataBinding;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerViewUtils;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.BindingAdapter;
import com.drake.brv.animation.AlphaItemAnimation;
import com.drake.brv.animation.ItemAnimation;
import com.drake.brv.item.ItemAttached;
import com.drake.brv.item.ItemBind;
import com.drake.brv.item.ItemExpand;
import com.drake.brv.item.ItemHover;
import com.drake.brv.item.ItemPosition;
import com.drake.brv.item.ItemStableId;
import com.drake.brv.listener.DefaultItemTouchCallback;
import com.drake.brv.listener.ItemDifferCallback;
import com.drake.brv.listener.OnBindViewHolderListener;
import com.drake.brv.listener.OnHoverAttachListener;
import com.drake.brv.listener.ProxyDiffCallback;
import com.drake.brv.listener.ThrottleClickListener;
import com.drake.brv.utils.BRV;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.reflect.KType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000Ê\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010!\n\u0002\u0010\u0000\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0014\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b9\n\u0002\u0010\u0015\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0016\u0018\u0000 Ô\u00012\f\u0012\b\u0012\u00060\u0002R\u00020\u00000\u0001:\u0004Ó\u0001Ô\u0001B\u0005¢\u0006\u0002\u0010\u0003J(\u0010\u008f\u0001\u001a\u00020\"2\t\u0010\u0090\u0001\u001a\u0004\u0018\u00010\u00062\t\b\u0003\u0010\u0091\u0001\u001a\u00020\u00152\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ(\u0010\u0093\u0001\u001a\u00020\"2\t\u0010\u0090\u0001\u001a\u0004\u0018\u00010\u00062\t\b\u0003\u0010\u0091\u0001\u001a\u00020\u00152\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ8\u0010\u0094\u0001\u001a\u00020\"\"\u0007\b\u0000\u0010\u0095\u0001\u0018\u00012 \b\b\u0010\u0096\u0001\u001a\u0019\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\u00150!¢\u0006\u0002\b#H\u0086\bø\u0001\u0000J1\u0010\u0097\u0001\u001a\u00020\"2\u0010\u0010Z\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0006\u0018\u00010\u00192\t\b\u0002\u0010\u0092\u0001\u001a\u00020\f2\t\b\u0003\u0010\u0091\u0001\u001a\u00020\u0015H\u0007JH\u0010\u0098\u0001\u001a\u00020\"\"\u0007\b\u0000\u0010\u0095\u0001\u0018\u000120\b\b\u0010\u0096\u0001\u001a)\u0012\u0005\u0012\u0003H\u0095\u0001\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(j\u0012\u0004\u0012\u00020\u00150!¢\u0006\u0002\b#H\u0086\bø\u0001\u0000J\u001e\u0010\u0098\u0001\u001a\u00020\"\"\u0007\b\u0000\u0010\u0095\u0001\u0018\u00012\t\b\u0001\u0010\u0099\u0001\u001a\u00020\u0015H\u0086\bJ\u0011\u0010\u009a\u0001\u001a\u00020\"2\b\b\u0002\u0010k\u001a\u00020\fJ\u0007\u0010\u009b\u0001\u001a\u00020\"J\u0011\u0010\u009c\u0001\u001a\u00020\"2\b\b\u0001\u0010j\u001a\u00020\u0015J\u0012\u0010\u009d\u0001\u001a\u00020\"2\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ\u0012\u0010\u009e\u0001\u001a\u00020\"2\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ\u001c\u0010\u009f\u0001\u001a\u00020\u00152\b\b\u0001\u0010j\u001a\u00020\u00152\t\b\u0003\u0010 \u0001\u001a\u00020\u0015J'\u0010¡\u0001\u001a\u00020\u00152\b\b\u0001\u0010j\u001a\u00020\u00152\t\b\u0002\u0010¢\u0001\u001a\u00020\f2\t\b\u0003\u0010 \u0001\u001a\u00020\u0015J'\u0010£\u0001\u001a\u00020\u00152\b\b\u0001\u0010j\u001a\u00020\u00152\t\b\u0002\u0010¢\u0001\u001a\u00020\f2\t\b\u0003\u0010 \u0001\u001a\u00020\u0015J?\u0010¤\u0001\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00052\u000e\u0010Z\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00052\u000b\b\u0002\u0010¡\u0001\u001a\u0004\u0018\u00010\f2\t\b\u0003\u0010 \u0001\u001a\u00020\u0015H\u0002¢\u0006\u0003\u0010¥\u0001J\u0017\u0010¦\u0001\u001a\b\u0018\u00010\u0002R\u00020\u00002\u0006\u0010j\u001a\u00020\u0015H\u0002J\u0015\u0010§\u0001\u001a\t\u0012\u0005\u0012\u0003H\u0095\u00010\u0019\"\u0005\b\u0000\u0010\u0095\u0001J\t\u0010¨\u0001\u001a\u00020\u0015H\u0016J\u0011\u0010©\u0001\u001a\u00020&2\u0006\u0010j\u001a\u00020\u0015H\u0016J\u0011\u0010ª\u0001\u001a\u00020\u00152\u0006\u0010j\u001a\u00020\u0015H\u0016J\u001f\u0010«\u0001\u001a\u0003H\u0095\u0001\"\u0005\b\u0000\u0010\u0095\u00012\b\b\u0001\u0010j\u001a\u00020\u0015¢\u0006\u0003\u0010¬\u0001J$\u0010\u00ad\u0001\u001a\u0005\u0018\u0001H\u0095\u0001\"\u0007\b\u0000\u0010\u0095\u0001\u0018\u00012\u0006\u0010j\u001a\u00020\u0015H\u0086\b¢\u0006\u0003\u0010¬\u0001J\u0007\u0010®\u0001\u001a\u00020\fJ\u0011\u0010¯\u0001\u001a\u00020\f2\b\b\u0001\u0010j\u001a\u00020\u0015J\u0011\u0010°\u0001\u001a\u00020\f2\b\b\u0001\u0010j\u001a\u00020\u0015J\u000f\u0010±\u0001\u001a\u00020\f2\u0006\u0010j\u001a\u00020\u0015J\u0011\u0010²\u0001\u001a\u00020\f2\b\b\u0001\u0010j\u001a\u00020\u0015J\u001c\u0010³\u0001\u001a\u00020\f2\b\b\u0001\u0010j\u001a\u00020\u00152\t\b\u0001\u0010´\u0001\u001a\u00020\u0015J\u0013\u0010µ\u0001\u001a\u00020\"2\b\u0010¶\u0001\u001a\u00030\u0080\u0001H\u0016J$\u0010`\u001a\u00020\"2\u001c\u0010\u0096\u0001\u001a\u0017\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\"0a¢\u0006\u0002\b#J\u001e\u0010·\u0001\u001a\u00020\"2\u000b\u0010¸\u0001\u001a\u00060\u0002R\u00020\u00002\u0006\u0010j\u001a\u00020\u0015H\u0016J,\u0010·\u0001\u001a\u00020\"2\u000b\u0010¸\u0001\u001a\u00060\u0002R\u00020\u00002\u0006\u0010j\u001a\u00020\u00152\f\u0010z\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005H\u0016JT\u0010f\u001a\u00020\"2L\u0010\u0096\u0001\u001aG\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(j\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(k\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(l\u0012\u0004\u0012\u00020\"0gJI\u0010m\u001a\u00020\"2\u000e\b\u0001\u0010¹\u0001\u001a\u00030º\u0001\"\u00020\u001521\u0010\u0096\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#J9\u0010o\u001a\u00020\"21\u0010\u0096\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(p\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#J\u001f\u0010»\u0001\u001a\u00060\u0002R\u00020\u00002\b\u0010¼\u0001\u001a\u00030½\u00012\u0006\u0010p\u001a\u00020\u0015H\u0016J*\u0010q\u001a\u00020\"2\"\u0010\u0096\u0001\u001a\u001d\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#JJ\u0010¾\u0001\u001a\u00020\"2\u000e\b\u0001\u0010¹\u0001\u001a\u00030º\u0001\"\u00020\u001521\u0010\u0096\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#JI\u0010x\u001a\u00020\"2\u000e\b\u0001\u0010¹\u0001\u001a\u00030º\u0001\"\u00020\u001521\u0010\u0096\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#J?\u0010y\u001a\u00020\"27\u0010\u0096\u0001\u001a2\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00060\u0005¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(z\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#JT\u0010{\u001a\u00020\"2L\u0010\u0096\u0001\u001aG\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(j\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(|\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(}\u0012\u0004\u0012\u00020\"0gJ\u0016\u0010¿\u0001\u001a\u00020\"2\u000b\u0010¸\u0001\u001a\u00060\u0002R\u00020\u0000H\u0016J\u0016\u0010À\u0001\u001a\u00020\"2\u000b\u0010¸\u0001\u001a\u00060\u0002R\u00020\u0000H\u0016J\u001d\u0010Á\u0001\u001a\u00020\"2\t\u0010\u0090\u0001\u001a\u0004\u0018\u00010\u00062\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ\u001d\u0010Â\u0001\u001a\u00020\"2\t\b\u0003\u0010\u0091\u0001\u001a\u00020\u00152\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ\u001d\u0010Ã\u0001\u001a\u00020\"2\t\u0010\u0090\u0001\u001a\u0004\u0018\u00010\u00062\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ\u001d\u0010Ä\u0001\u001a\u00020\"2\t\b\u0003\u0010\u0091\u0001\u001a\u00020\u00152\t\b\u0002\u0010\u0092\u0001\u001a\u00020\fJ\u000f\u0010Å\u0001\u001a\u00020\"2\u0006\u0010D\u001a\u00020EJ\u0011\u0010Å\u0001\u001a\u00020\"2\b\u0010Æ\u0001\u001a\u00030Ç\u0001J\u0017\u0010È\u0001\u001a\u00020\"2\u000e\b\u0001\u0010É\u0001\u001a\u00030º\u0001\"\u00020\u0015J\u0019\u0010Ê\u0001\u001a\u00020\"2\b\b\u0001\u0010j\u001a\u00020\u00152\u0006\u0010k\u001a\u00020\fJ3\u0010Ë\u0001\u001a\u00020\"2\u0011\u0010Ì\u0001\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0006\u0018\u00010\u00192\t\b\u0002\u0010Í\u0001\u001a\u00020\f2\f\b\u0002\u0010Î\u0001\u001a\u0005\u0018\u00010Ï\u0001J\u0007\u0010Ð\u0001\u001a\u00020\"J\u000f\u0010Ð\u0001\u001a\u00020\"2\u0006\u0010|\u001a\u00020\fJ=\u0010m\u001a\u00020\"*\u00020\u001521\u0010Ñ\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#J>\u0010¾\u0001\u001a\u00020\"*\u00020\u001521\u0010Ñ\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#J=\u0010x\u001a\u00020\"*\u00020\u001521\u0010Ñ\u0001\u001a,\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"0!¢\u0006\u0002\b#J\u000b\u0010Ò\u0001\u001a\u00020\u0015*\u00020\u0015R$\u0010\u0004\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0006\u0018\u00010\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0007\u0010\b\"\u0004\b\t\u0010\nR\u001a\u0010\u000b\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010R\u001a\u0010\u0011\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0012\u0010\u000e\"\u0004\b\u0013\u0010\u0010R\u0014\u0010\u0014\u001a\u00020\u00158BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u0016\u0010\u0017R\u0016\u0010\u0018\u001a\n\u0012\u0004\u0012\u00020\u0015\u0018\u00010\u0019X\u0082\u000e¢\u0006\u0002\n\u0000R\u0011\u0010\u001a\u001a\u00020\u00158F¢\u0006\u0006\u001a\u0004\b\u001b\u0010\u0017R\u0017\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00150\u0005¢\u0006\b\n\u0000\u001a\u0004\b\u001d\u0010\bR|\u0010\u001e\u001ap\u0012\u0004\u0012\u00020\u0015\u0012-\u0012+\u0012!\u0012\u001f\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#\u0012\u0004\u0012\u00020\f0 0\u001fj7\u0012\u0004\u0012\u00020\u0015\u0012-\u0012+\u0012!\u0012\u001f\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#\u0012\u0004\u0012\u00020\f0 `$X\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010%\u001a\u00020&X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b'\u0010(\"\u0004\b)\u0010*R\u0010\u0010+\u001a\u0004\u0018\u00010,X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010-\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010\u000e\"\u0004\b/\u0010\u0010R\u0011\u00100\u001a\u00020\u00158F¢\u0006\u0006\u001a\u0004\b1\u0010\u0017R4\u00103\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00192\u000e\u00102\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u0019@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b4\u0010\b\"\u0004\b5\u0010\nR\u0011\u00106\u001a\u00020\u00158F¢\u0006\u0006\u001a\u0004\b7\u0010\u0017R4\u00108\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00192\u000e\u00102\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u0019@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b9\u0010\b\"\u0004\b:\u0010\nR\u001a\u0010;\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b<\u0010\u000e\"\u0004\b=\u0010\u0010R4\u0010>\u001a%\u0012\u0004\u0012\u00020@\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\u00150!¢\u0006\u0002\b#0?¢\u0006\b\n\u0000\u001a\u0004\bA\u0010BR\u000e\u0010C\u001a\u00020\fX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010D\u001a\u00020EX\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u0010F\u001a\u00020GX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bH\u0010I\"\u0004\bJ\u0010KR(\u0010M\u001a\u0004\u0018\u00010L2\b\u00102\u001a\u0004\u0018\u00010L@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bN\u0010O\"\u0004\bP\u0010QR\u000e\u0010R\u001a\u00020\u0015X\u0082\u000e¢\u0006\u0002\n\u0000Rd\u0010S\u001aX\u0012\u0004\u0012\u00020\u0015\u0012!\u0012\u001f\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#0\u001fj+\u0012\u0004\u0012\u00020\u0015\u0012!\u0012\u001f\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#`$X\u0082\u0004¢\u0006\u0002\n\u0000R\u0011\u0010T\u001a\u00020\u00158F¢\u0006\u0006\u001a\u0004\bU\u0010\u0017R\u001a\u0010V\u001a\u00020\u0015X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bW\u0010\u0017\"\u0004\bX\u0010YR8\u0010Z\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0006\u0018\u00010\u00192\u0010\u00102\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0006\u0018\u00010\u00198F@GX\u0086\u000e¢\u0006\f\u001a\u0004\b[\u0010\b\"\u0004\b\\\u0010\nR4\u0010]\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00052\u000e\u00102\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00058F@FX\u0086\u000e¢\u0006\f\u001a\u0004\b^\u0010\b\"\u0004\b_\u0010\nR%\u0010`\u001a\u0019\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\"\u0018\u00010a¢\u0006\u0002\b#X\u0082\u000e¢\u0006\u0002\n\u0000R \u0010b\u001a\b\u0012\u0004\u0012\u00020c0\u0005X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bd\u0010\b\"\u0004\be\u0010\nRU\u0010f\u001aI\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(j\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(k\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(l\u0012\u0004\u0012\u00020\"\u0018\u00010gX\u0082\u000e¢\u0006\u0002\n\u0000R:\u0010m\u001a.\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#X\u0082\u000e¢\u0006\u0002\n\u0000R:\u0010o\u001a.\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(p\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#X\u0082\u000e¢\u0006\u0002\n\u0000R+\u0010q\u001a\u001f\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#X\u0082\u000e¢\u0006\u0002\n\u0000R\u001c\u0010r\u001a\u0004\u0018\u00010sX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bt\u0010u\"\u0004\bv\u0010wR:\u0010x\u001a.\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(n\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#X\u0082\u000e¢\u0006\u0002\n\u0000R@\u0010y\u001a4\u0012\b\u0012\u00060\u0002R\u00020\u0000\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00060\u0005¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(z\u0012\u0004\u0012\u00020\"\u0018\u00010!¢\u0006\u0002\b#X\u0082\u000e¢\u0006\u0002\n\u0000RU\u0010{\u001aI\u0012\u0013\u0012\u00110\u0015¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(j\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(|\u0012\u0013\u0012\u00110\f¢\u0006\f\bh\u0012\b\bi\u0012\u0004\b\b(}\u0012\u0004\u0012\u00020\"\u0018\u00010gX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010~\u001a\u00020\u0015X\u0082\u000e¢\u0006\u0002\n\u0000R!\u0010\u007f\u001a\u0005\u0018\u00010\u0080\u0001X\u0086\u000e¢\u0006\u0012\n\u0000\u001a\u0006\b\u0081\u0001\u0010\u0082\u0001\"\u0006\b\u0083\u0001\u0010\u0084\u0001R\u001d\u0010\u0085\u0001\u001a\u00020\fX\u0086\u000e¢\u0006\u0010\n\u0000\u001a\u0005\b\u0086\u0001\u0010\u000e\"\u0005\b\u0087\u0001\u0010\u0010R'\u0010\u0088\u0001\u001a\u00020\f2\u0006\u00102\u001a\u00020\f@FX\u0086\u000e¢\u0006\u0010\n\u0000\u001a\u0005\b\u0089\u0001\u0010\u000e\"\u0005\b\u008a\u0001\u0010\u0010R \u0010|\u001a\u00020\f2\u0007\u0010\u008b\u0001\u001a\u00020\f@BX\u0086\u000e¢\u0006\t\n\u0000\u001a\u0005\b\u008c\u0001\u0010\u000eR6\u0010\u008d\u0001\u001a%\u0012\u0004\u0012\u00020@\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0015\u0012\u0004\u0012\u00020\u00150!¢\u0006\u0002\b#0?¢\u0006\t\n\u0000\u001a\u0005\b\u008e\u0001\u0010B\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006Õ\u0001"}, m5311d2 = {"Lcom/drake/brv/BindingAdapter;", "Landroidx/recyclerview/widget/RecyclerView$Adapter;", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "()V", "_data", "", "", "get_data", "()Ljava/util/List;", "set_data", "(Ljava/util/List;)V", "animationEnabled", "", "getAnimationEnabled", "()Z", "setAnimationEnabled", "(Z)V", "animationRepeat", "getAnimationRepeat", "setAnimationRepeat", "checkableCount", "", "getCheckableCount", "()I", "checkableItemTypeList", "", "checkedCount", "getCheckedCount", "checkedPosition", "getCheckedPosition", "clickListeners", "Ljava/util/HashMap;", "Lkotlin/Pair;", "Lkotlin/Function2;", "", "Lkotlin/ExtensionFunctionType;", "Lkotlin/collections/HashMap;", "clickThrottle", "", "getClickThrottle", "()J", "setClickThrottle", "(J)V", "context", "Landroid/content/Context;", "expandAnimationEnabled", "getExpandAnimationEnabled", "setExpandAnimationEnabled", "footerCount", "getFooterCount", "value", "footers", "getFooters", "setFooters", "headerCount", "getHeaderCount", "headers", "getHeaders", "setHeaders", "hoverEnabled", "getHoverEnabled", "setHoverEnabled", "interfacePool", "", "Lkotlin/reflect/KType;", "getInterfacePool", "()Ljava/util/Map;", "isFirst", "itemAnimation", "Lcom/drake/brv/animation/ItemAnimation;", "itemDifferCallback", "Lcom/drake/brv/listener/ItemDifferCallback;", "getItemDifferCallback", "()Lcom/drake/brv/listener/ItemDifferCallback;", "setItemDifferCallback", "(Lcom/drake/brv/listener/ItemDifferCallback;)V", "Landroidx/recyclerview/widget/ItemTouchHelper;", "itemTouchHelper", "getItemTouchHelper", "()Landroidx/recyclerview/widget/ItemTouchHelper;", "setItemTouchHelper", "(Landroidx/recyclerview/widget/ItemTouchHelper;)V", "lastPosition", "longClickListeners", "modelCount", "getModelCount", "modelId", "getModelId", "setModelId", "(I)V", "models", "getModels", "setModels", "mutable", "getMutable", "setMutable", "onBind", "Lkotlin/Function1;", "onBindViewHolders", "Lcom/drake/brv/listener/OnBindViewHolderListener;", "getOnBindViewHolders", "setOnBindViewHolders", "onChecked", "Lkotlin/Function3;", "Lkotlin/ParameterName;", "name", "position", "checked", "allChecked", "onClick", "viewId", "onCreate", "viewType", "onExpand", "onHoverAttachListener", "Lcom/drake/brv/listener/OnHoverAttachListener;", "getOnHoverAttachListener", "()Lcom/drake/brv/listener/OnHoverAttachListener;", "setOnHoverAttachListener", "(Lcom/drake/brv/listener/OnHoverAttachListener;)V", "onLongClick", "onPayload", "payloads", "onToggle", "toggleMode", "end", "previousExpandPosition", "rv", "Landroidx/recyclerview/widget/RecyclerView;", "getRv", "()Landroidx/recyclerview/widget/RecyclerView;", "setRv", "(Landroidx/recyclerview/widget/RecyclerView;)V", "singleExpandMode", "getSingleExpandMode", "setSingleExpandMode", "singleMode", "getSingleMode", "setSingleMode", "<set-?>", "getToggleMode", "typePool", "getTypePool", "addFooter", "model", "index", "animation", "addHeader", "addInterfaceType", "M", "block", "addModels", "addType", "layout", "checkedAll", "checkedReverse", "checkedSwitch", "clearFooter", "clearHeader", "collapse", "depth", "expand", "scrollTop", "expandOrCollapse", "flat", "(Ljava/util/List;Ljava/lang/Boolean;I)Ljava/util/List;", "getBindViewHolder", "getCheckedModels", "getItemCount", "getItemId", "getItemViewType", "getModel", "(I)Ljava/lang/Object;", "getModelOrNull", "isCheckedAll", "isFooter", "isHeader", "isHover", "isModel", "isSameGroup", "otherPosition", "onAttachedToRecyclerView", "recyclerView", "onBindViewHolder", "holder", "id", "", "onCreateViewHolder", "parent", "Landroid/view/ViewGroup;", "onFastClick", "onViewAttachedToWindow", "onViewDetachedFromWindow", "removeFooter", "removeFooterAt", "removeHeader", "removeHeaderAt", "setAnimation", "animationType", "Lcom/drake/brv/annotaion/AnimationType;", "setCheckableType", "checkableItemType", "setChecked", "setDifferModels", "newModels", "detectMoves", "commitCallback", "Ljava/lang/Runnable;", "toggle", "listener", "toModelPosition", "BindingViewHolder", "Companion", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public class BindingAdapter extends RecyclerView.Adapter<BindingViewHolder> {

    /* renamed from: a */
    @NotNull
    public static final C3233b f8897a = new C3233b(null);

    /* renamed from: b */
    @NotNull
    public static final Lazy<Boolean> f8898b = LazyKt__LazyJVMKt.lazy(C3232a.f8934c);

    /* renamed from: A */
    public boolean f8899A;

    /* renamed from: B */
    @Nullable
    public OnHoverAttachListener f8900B;

    /* renamed from: c */
    @Nullable
    public RecyclerView f8901c;

    /* renamed from: f */
    @Nullable
    public Function1<? super BindingViewHolder, Unit> f8904f;

    /* renamed from: g */
    @Nullable
    public Function2<? super BindingViewHolder, ? super Integer, Unit> f8905g;

    /* renamed from: h */
    @Nullable
    public Function3<? super Integer, ? super Boolean, ? super Boolean, Unit> f8906h;

    /* renamed from: i */
    @Nullable
    public Function3<? super Integer, ? super Boolean, ? super Boolean, Unit> f8907i;

    /* renamed from: j */
    @Nullable
    public Context f8908j;

    /* renamed from: v */
    @Nullable
    public List<Object> f8920v;

    /* renamed from: w */
    @NotNull
    public ItemDifferCallback f8921w;

    /* renamed from: x */
    public boolean f8922x;

    /* renamed from: y */
    @NotNull
    public final List<Integer> f8923y;

    /* renamed from: z */
    public boolean f8924z;

    /* renamed from: d */
    @NotNull
    public List<OnBindViewHolderListener> f8902d = new ArrayList();

    /* renamed from: e */
    public int f8903e = BRV.f2870a;

    /* renamed from: k */
    @NotNull
    public final Map<KType, Function2<Object, Integer, Integer>> f8909k = new LinkedHashMap();

    /* renamed from: l */
    @NotNull
    public final Map<KType, Function2<Object, Integer, Integer>> f8910l = new LinkedHashMap();

    /* renamed from: m */
    @NotNull
    public final HashMap<Integer, Pair<Function2<BindingViewHolder, Integer, Unit>, Boolean>> f8911m = new HashMap<>();

    /* renamed from: n */
    @NotNull
    public final HashMap<Integer, Function2<BindingViewHolder, Integer, Unit>> f8912n = new HashMap<>();

    /* renamed from: o */
    @Nullable
    public ItemTouchHelper f8913o = new ItemTouchHelper(new DefaultItemTouchCallback());

    /* renamed from: p */
    public long f8914p = 500;

    /* renamed from: q */
    @NotNull
    public ItemAnimation f8915q = new AlphaItemAnimation(0.0f, 1);

    /* renamed from: r */
    public int f8916r = -1;

    /* renamed from: s */
    public boolean f8917s = true;

    /* renamed from: t */
    @NotNull
    public List<? extends Object> f8918t = new ArrayList();

    /* renamed from: u */
    @NotNull
    public List<? extends Object> f8919u = new ArrayList();

    @Metadata(m5310d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"<anonymous>", "", "invoke", "()Ljava/lang/Boolean;"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.BindingAdapter$a */
    public static final class C3232a extends Lambda implements Function0<Boolean> {

        /* renamed from: c */
        public static final C3232a f8934c = new C3232a();

        public C3232a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Boolean invoke() {
            boolean z;
            try {
                Class.forName("androidx.databinding.DataBindingUtil");
                z = true;
            } catch (Throwable unused) {
                z = false;
            }
            return Boolean.valueOf(z);
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u001b\u0010\u0003\u001a\u00020\u00048BX\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0007\u0010\b\u001a\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/drake/brv/BindingAdapter$Companion;", "", "()V", "dataBindingEnable", "", "getDataBindingEnable", "()Z", "dataBindingEnable$delegate", "Lkotlin/Lazy;", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.brv.BindingAdapter$b */
    public static final class C3233b {
        public C3233b(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    public BindingAdapter() {
        int i2 = ItemDifferCallback.f2865a;
        this.f8921w = ItemDifferCallback.a.f2866b;
        this.f8923y = new ArrayList();
        this.f8899A = true;
    }

    /* renamed from: a */
    public static void m3923a(final BindingAdapter bindingAdapter, List list, boolean z, int i2, int i3, Object obj) {
        int size;
        if ((i3 & 2) != 0) {
            z = true;
        }
        if ((i3 & 4) != 0) {
            i2 = -1;
        }
        if (list == null || list.isEmpty()) {
            return;
        }
        List mutableList = list instanceof ArrayList ? list : CollectionsKt___CollectionsKt.toMutableList((Collection) list);
        List<Object> list2 = bindingAdapter.f8920v;
        if (list2 == null) {
            m3924d(bindingAdapter, mutableList, null, 0, 6, null);
            bindingAdapter.m3939q(mutableList);
            bindingAdapter.notifyDataSetChanged();
            return;
        }
        if (list2.isEmpty()) {
            List<Object> list3 = bindingAdapter.f8920v;
            if (!TypeIntrinsics.isMutableList(list3)) {
                list3 = null;
            }
            if (list3 == null) {
                return;
            }
            m3924d(bindingAdapter, mutableList, null, 0, 6, null);
            list3.addAll(mutableList);
            bindingAdapter.notifyDataSetChanged();
            return;
        }
        List<Object> list4 = bindingAdapter.f8920v;
        Objects.requireNonNull(list4, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.Any?>");
        List asMutableList = TypeIntrinsics.asMutableList(list4);
        int m3929f = bindingAdapter.m3929f();
        if (i2 == -1 || asMutableList.size() < i2) {
            size = asMutableList.size() + m3929f;
            m3924d(bindingAdapter, mutableList, null, 0, 6, null);
            asMutableList.addAll(mutableList);
        } else {
            if (!bindingAdapter.f8923y.isEmpty()) {
                int size2 = list.size();
                ListIterator<Integer> listIterator = bindingAdapter.f8923y.listIterator();
                while (listIterator.hasNext()) {
                    listIterator.set(Integer.valueOf(listIterator.next().intValue() + size2));
                }
            }
            size = m3929f + i2;
            m3924d(bindingAdapter, mutableList, null, 0, 6, null);
            asMutableList.addAll(i2, mutableList);
        }
        if (!z) {
            bindingAdapter.notifyDataSetChanged();
            return;
        }
        bindingAdapter.notifyItemRangeInserted(size, mutableList.size());
        RecyclerView recyclerView = bindingAdapter.f8901c;
        if (recyclerView == null) {
            return;
        }
        recyclerView.post(new Runnable() { // from class: b.i.a.d
            @Override // java.lang.Runnable
            public final void run() {
                BindingAdapter this$0 = BindingAdapter.this;
                BindingAdapter.C3233b c3233b = BindingAdapter.f8897a;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                RecyclerView recyclerView2 = this$0.f8901c;
                if (recyclerView2 == null) {
                    return;
                }
                recyclerView2.invalidateItemDecorations();
            }
        });
    }

    /* renamed from: d */
    public static /* synthetic */ List m3924d(BindingAdapter bindingAdapter, List list, Boolean bool, int i2, int i3, Object obj) {
        int i4 = i3 & 2;
        if ((i3 & 4) != 0) {
            i2 = 0;
        }
        bindingAdapter.m3927c(list, null, i2);
        return list;
    }

    /* renamed from: p */
    public static void m3925p(final BindingAdapter bindingAdapter, List list, boolean z, Runnable runnable, int i2, Object obj) {
        List list2;
        boolean z2 = (i2 & 2) != 0 ? true : z;
        int i3 = i2 & 4;
        List<Object> list3 = bindingAdapter.f8920v;
        final Runnable runnable2 = null;
        if (list instanceof ArrayList) {
            m3924d(bindingAdapter, list, null, 0, 6, null);
            list2 = list;
        } else if (list != null) {
            list2 = CollectionsKt___CollectionsKt.toMutableList((Collection) list);
            m3924d(bindingAdapter, list2, null, 0, 6, null);
        } else {
            list2 = null;
        }
        bindingAdapter.f8920v = list2;
        final DiffUtil.DiffResult calculateDiff = DiffUtil.calculateDiff(new ProxyDiffCallback(list, list3, bindingAdapter.f8921w), z2);
        Intrinsics.checkNotNullExpressionValue(calculateDiff, "calculateDiff(ProxyDiffC…erCallback), detectMoves)");
        Looper mainLooper = Looper.getMainLooper();
        if (Intrinsics.areEqual(Looper.myLooper(), mainLooper)) {
            calculateDiff.dispatchUpdatesTo(bindingAdapter);
        } else {
            new Handler(mainLooper).post(new Runnable() { // from class: b.i.a.c
                @Override // java.lang.Runnable
                public final void run() {
                    DiffUtil.DiffResult diffResult = DiffUtil.DiffResult.this;
                    BindingAdapter this$0 = bindingAdapter;
                    Runnable runnable3 = runnable2;
                    BindingAdapter.C3233b c3233b = BindingAdapter.f8897a;
                    Intrinsics.checkNotNullParameter(diffResult, "$diffResult");
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    diffResult.dispatchUpdatesTo(this$0);
                    if (runnable3 == null) {
                        return;
                    }
                    runnable3.run();
                }
            });
        }
        bindingAdapter.f8923y.clear();
        if (!bindingAdapter.f8917s) {
            bindingAdapter.f8916r = bindingAdapter.getItemCount() - 1;
        } else {
            bindingAdapter.f8916r = -1;
            bindingAdapter.f8917s = false;
        }
    }

    /* renamed from: b */
    public final void m3926b(boolean z) {
        int i2 = 0;
        if (!z) {
            int itemCount = getItemCount();
            int i3 = 0;
            while (i3 < itemCount) {
                int i4 = i3 + 1;
                if (this.f8923y.contains(Integer.valueOf(i3))) {
                    m3938o(i3, false);
                }
                i3 = i4;
            }
            return;
        }
        if (this.f8924z) {
            return;
        }
        int itemCount2 = getItemCount();
        while (i2 < itemCount2) {
            int i5 = i2 + 1;
            if (!this.f8923y.contains(Integer.valueOf(i2))) {
                m3938o(i2, true);
            }
            i2 = i5;
        }
    }

    /* renamed from: c */
    public final List<Object> m3927c(List<Object> list, Boolean bool, @IntRange(from = -1) int i2) {
        int i3;
        List<Object> m1199d;
        boolean z;
        if (list.isEmpty()) {
            return list;
        }
        ArrayList arrayList = new ArrayList(list);
        list.clear();
        Iterator it = arrayList.iterator();
        List<Object> list2 = null;
        int i4 = 0;
        while (it.hasNext()) {
            Object next = it.next();
            if (list2 != null) {
                if (!list.isEmpty()) {
                    Iterator<T> it2 = list.iterator();
                    while (it2.hasNext()) {
                        if (next == it2.next()) {
                            z = true;
                            break;
                        }
                    }
                }
                z = false;
                if (z) {
                }
            }
            list.add(next);
            if (next instanceof ItemExpand) {
                ItemExpand itemExpand = (ItemExpand) next;
                itemExpand.m1196a(i4);
                if (bool != null && i2 != 0) {
                    itemExpand.m1198c(bool.booleanValue());
                    if (i2 > 0) {
                        i3 = i2 - 1;
                        m1199d = itemExpand.m1199d();
                        if (m1199d != null && (true ^ m1199d.isEmpty()) && (itemExpand.m1197b() || (i2 != 0 && bool != null))) {
                            list.addAll(m3927c(CollectionsKt___CollectionsKt.toMutableList((Collection) m1199d), bool, i3));
                        }
                        list2 = m1199d;
                    }
                }
                i3 = i2;
                m1199d = itemExpand.m1199d();
                if (m1199d != null) {
                    list.addAll(m3927c(CollectionsKt___CollectionsKt.toMutableList((Collection) m1199d), bool, i3));
                }
                list2 = m1199d;
            } else {
                list2 = null;
            }
            i4++;
        }
        return list;
    }

    @NotNull
    /* renamed from: e */
    public final <M> List<M> m3928e() {
        ArrayList arrayList = new ArrayList();
        Iterator<Integer> it = this.f8923y.iterator();
        while (it.hasNext()) {
            arrayList.add(m3930g(it.next().intValue()));
        }
        return arrayList;
    }

    /* renamed from: f */
    public final int m3929f() {
        return this.f8918t.size();
    }

    /* renamed from: g */
    public final <M> M m3930g(@IntRange(from = 0) int i2) {
        if (m3933j(i2)) {
            return (M) this.f8918t.get(i2);
        }
        if (m3932i(i2)) {
            return (M) this.f8919u.get((i2 - m3929f()) - m3931h());
        }
        List<Object> list = this.f8920v;
        Intrinsics.checkNotNull(list);
        return (M) list.get(i2 - m3929f());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return m3931h() + m3929f() + this.f8919u.size();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public long getItemId(int position) {
        if (m3933j(position)) {
            Object obj = this.f8918t.get(position);
            r1 = obj instanceof ItemStableId ? obj : null;
        } else if (m3932i(position)) {
            Object obj2 = this.f8919u.get((position - m3929f()) - m3931h());
            r1 = obj2 instanceof ItemStableId ? obj2 : null;
        } else {
            List<Object> list = this.f8920v;
            if (list != null) {
                Object orNull = CollectionsKt___CollectionsKt.getOrNull(list, position - m3929f());
                r1 = orNull instanceof ItemStableId ? orNull : null;
            }
        }
        if (r1 == null) {
            return -1L;
        }
        return r1.getItemId();
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x00cc, code lost:
    
        if (r2 != null) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00cf, code lost:
    
        r6 = r2.invoke(r0, java.lang.Integer.valueOf(r11));
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00da, code lost:
    
        if (r6 == null) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:?, code lost:
    
        return r6.intValue();
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00e1, code lost:
    
        r1 = p005b.p131d.p132a.p133a.C1499a.m586H("Please add item model type : addType<");
        r1.append((java.lang.Object) r0.getClass().getName());
        r1.append(">(R.layout.item)");
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0100, code lost:
    
        throw new android.util.NoSuchPropertyException(r1.toString());
     */
    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int getItemViewType(int r11) {
        /*
            Method dump skipped, instructions count: 262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.drake.brv.BindingAdapter.getItemViewType(int):int");
    }

    /* renamed from: h */
    public final int m3931h() {
        List<Object> list = this.f8920v;
        if (list == null) {
            return 0;
        }
        Intrinsics.checkNotNull(list);
        return list.size();
    }

    /* renamed from: i */
    public final boolean m3932i(@IntRange(from = 0) int i2) {
        if (this.f8919u.size() > 0) {
            if (i2 >= m3931h() + m3929f() && i2 < getItemCount()) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: j */
    public final boolean m3933j(@IntRange(from = 0) int i2) {
        return m3929f() > 0 && i2 < m3929f();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: k */
    public final boolean m3934k(int i2) {
        if (m3933j(i2)) {
            Object obj = this.f8918t.get(i2);
            r1 = obj instanceof ItemHover ? obj : null;
        } else if (m3932i(i2)) {
            Object obj2 = this.f8919u.get((i2 - m3929f()) - m3931h());
            r1 = obj2 instanceof ItemHover ? obj2 : null;
        } else {
            List<Object> list = this.f8920v;
            if (list != null) {
                Object orNull = CollectionsKt___CollectionsKt.getOrNull(list, i2 - m3929f());
                r1 = orNull instanceof ItemHover ? orNull : null;
            }
        }
        return r1 != null && r1.m1200a() && this.f8899A;
    }

    /* renamed from: l */
    public final void m3935l(@NotNull Function1<? super BindingViewHolder, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        this.f8904f = block;
    }

    /* renamed from: m */
    public final void m3936m(@NotNull Function3<? super Integer, ? super Boolean, ? super Boolean, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        this.f8906h = block;
    }

    /* renamed from: n */
    public final void m3937n(@IdRes @NotNull int[] id, @NotNull Function2<? super BindingViewHolder, ? super Integer, Unit> block) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(block, "block");
        int length = id.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = id[i2];
            i2++;
            this.f8911m.put(Integer.valueOf(i3), new Pair<>(block, Boolean.FALSE));
        }
        this.f8905g = block;
    }

    /* renamed from: o */
    public final void m3938o(@IntRange(from = 0) int i2, boolean z) {
        if (this.f8923y.contains(Integer.valueOf(i2)) && z) {
            return;
        }
        if (z || this.f8923y.contains(Integer.valueOf(i2))) {
            getItemViewType(i2);
            if (this.f8906h == null) {
                return;
            }
            if (z) {
                this.f8923y.add(Integer.valueOf(i2));
            } else {
                this.f8923y.remove(Integer.valueOf(i2));
            }
            if (this.f8924z && z && this.f8923y.size() > 1) {
                m3938o(this.f8923y.get(0).intValue(), false);
            }
            Function3<? super Integer, ? super Boolean, ? super Boolean, Unit> function3 = this.f8906h;
            if (function3 == null) {
                return;
            }
            Integer valueOf = Integer.valueOf(i2);
            Boolean valueOf2 = Boolean.valueOf(z);
            int size = this.f8923y.size();
            List<Object> list = this.f8920v;
            Intrinsics.checkNotNull(list);
            function3.invoke(valueOf, valueOf2, Boolean.valueOf(size == list.size()));
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onAttachedToRecyclerView(@NotNull RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        this.f8901c = recyclerView;
        if (this.f8908j == null) {
            this.f8908j = recyclerView.getContext();
        }
        ItemTouchHelper itemTouchHelper = this.f8913o;
        if (itemTouchHelper == null) {
            return;
        }
        itemTouchHelper.attachToRecyclerView(recyclerView);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(BindingViewHolder bindingViewHolder, int i2) {
        BindingViewHolder holder = bindingViewHolder;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object model = m3930g(i2);
        Objects.requireNonNull(holder);
        Intrinsics.checkNotNullParameter(model, "model");
        holder.f8928d = model;
        BindingAdapter bindingAdapter = holder.f8930f;
        for (OnBindViewHolderListener onBindViewHolderListener : bindingAdapter.f8902d) {
            RecyclerView recyclerView = bindingAdapter.f8901c;
            Intrinsics.checkNotNull(recyclerView);
            onBindViewHolderListener.mo1206a(recyclerView, holder.f8927c, holder, holder.getAdapterPosition());
        }
        if (model instanceof ItemPosition) {
            ((ItemPosition) model).m1201a(holder.getLayoutPosition() - holder.f8930f.m3929f());
        }
        if (model instanceof ItemBind) {
            ((ItemBind) model).m1194a(holder);
        }
        Function1<? super BindingViewHolder, Unit> function1 = holder.f8930f.f8904f;
        if (function1 != null) {
            function1.invoke(holder);
        }
        ViewBinding viewBinding = holder.f8929e;
        if (f8898b.getValue().booleanValue() && (viewBinding instanceof ViewDataBinding)) {
            try {
                ((ViewDataBinding) viewBinding).setVariable(holder.f8930f.f8903e, model);
                ((ViewDataBinding) viewBinding).executePendingBindings();
            } catch (Exception unused) {
                holder.f8926b.getResources().getResourceEntryName(holder.getItemViewType());
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public BindingViewHolder onCreateViewHolder(ViewGroup parent, int i2) {
        ViewDataBinding viewDataBinding;
        BindingViewHolder bindingViewHolder;
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = LayoutInflater.from(parent.getContext()).inflate(i2, parent, false);
        if (f8898b.getValue().booleanValue()) {
            try {
                viewDataBinding = DataBindingUtil.bind(itemView);
            } catch (Throwable unused) {
                viewDataBinding = null;
            }
            if (viewDataBinding == null) {
                Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
                bindingViewHolder = new BindingViewHolder(this, itemView);
            } else {
                bindingViewHolder = new BindingViewHolder(this, viewDataBinding);
            }
        } else {
            Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
            bindingViewHolder = new BindingViewHolder(this, itemView);
        }
        RecyclerViewUtils.setItemViewType(bindingViewHolder, i2);
        return bindingViewHolder;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onViewAttachedToWindow(BindingViewHolder bindingViewHolder) {
        BindingViewHolder holder = bindingViewHolder;
        Intrinsics.checkNotNullParameter(holder, "holder");
        holder.getLayoutPosition();
        Object m3942b = holder.m3942b();
        if (!(m3942b instanceof ItemAttached)) {
            m3942b = null;
        }
        ItemAttached itemAttached = (ItemAttached) m3942b;
        if (itemAttached == null) {
            return;
        }
        itemAttached.m1193b(holder);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onViewDetachedFromWindow(BindingViewHolder bindingViewHolder) {
        BindingViewHolder holder = bindingViewHolder;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object m3942b = holder.m3942b();
        if (!(m3942b instanceof ItemAttached)) {
            m3942b = null;
        }
        ItemAttached itemAttached = (ItemAttached) m3942b;
        if (itemAttached == null) {
            return;
        }
        itemAttached.m1192a(holder);
    }

    @SuppressLint({"NotifyDataSetChanged"})
    /* renamed from: q */
    public final void m3939q(@Nullable List<? extends Object> list) {
        if (list instanceof ArrayList) {
            m3924d(this, list, null, 0, 6, null);
        } else if (list != null) {
            list = CollectionsKt___CollectionsKt.toMutableList((Collection) list);
            m3924d(this, list, null, 0, 6, null);
        } else {
            list = null;
        }
        this.f8920v = list;
        notifyDataSetChanged();
        this.f8923y.clear();
        if (!this.f8917s) {
            this.f8916r = getItemCount() - 1;
        } else {
            this.f8916r = -1;
            this.f8917s = false;
        }
    }

    /* renamed from: r */
    public final void m3940r(boolean z) {
        this.f8924z = z;
        int size = this.f8923y.size();
        if (!this.f8924z || size <= 1) {
            return;
        }
        int i2 = size - 1;
        int i3 = 0;
        while (i3 < i2) {
            i3++;
            m3938o(this.f8923y.get(0).intValue(), false);
        }
    }

    public final void setOnHoverAttachListener(@Nullable OnHoverAttachListener onHoverAttachListener) {
        this.f8900B = onHoverAttachListener;
    }

    @Metadata(m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u000e\b\u0086\u0004\u0018\u00002\u00020\u0001B\u000f\b\u0016\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004B\u000f\b\u0016\u0012\u0006\u0010\u0005\u001a\u00020\u0006¢\u0006\u0002\u0010\u0007J\u0015\u0010&\u001a\u00020'2\u0006\u0010(\u001a\u00020\tH\u0000¢\u0006\u0002\b)J\u0010\u0010*\u001a\u00020\u00182\b\b\u0003\u0010+\u001a\u00020\u0018J\u001a\u0010,\u001a\u00020\u00182\b\b\u0002\u0010-\u001a\u00020.2\b\b\u0003\u0010+\u001a\u00020\u0018J\u001a\u0010/\u001a\u00020\u00182\b\b\u0002\u0010-\u001a\u00020.2\b\b\u0003\u0010+\u001a\u00020\u0018J\u0006\u00100\u001a\u00020\u0018J\f\u00101\u001a\b\u0018\u00010\u0000R\u00020\u000eJ!\u00102\u001a\u0002H3\"\n\b\u0000\u00103*\u0004\u0018\u00010\u00032\b\b\u0001\u00104\u001a\u00020\u0018¢\u0006\u0002\u00105J\u001a\u00106\u001a\u0002H7\"\n\b\u0000\u00107\u0018\u0001*\u00020\u001fH\u0086\b¢\u0006\u0002\u0010#J\u001c\u00108\u001a\u0004\u0018\u0001H7\"\n\b\u0000\u00107\u0018\u0001*\u00020\u001fH\u0086\b¢\u0006\u0002\u0010#J\u0011\u00109\u001a\u0002H:\"\u0004\b\u0000\u0010:¢\u0006\u0002\u0010\fJ\u0018\u0010;\u001a\u0004\u0018\u0001H:\"\u0006\b\u0000\u0010:\u0018\u0001H\u0086\b¢\u0006\u0002\u0010\fR\u001e\u0010\n\u001a\u00020\t2\u0006\u0010\b\u001a\u00020\t@BX\u0086.¢\u0006\b\n\u0000\u001a\u0004\b\u000b\u0010\fR\u0011\u0010\r\u001a\u00020\u000e¢\u0006\b\n\u0000\u001a\u0004\b\u000f\u0010\u0010R\u001a\u0010\u0011\u001a\u00020\u0012X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0016R\u0011\u0010\u0017\u001a\u00020\u00188F¢\u0006\u0006\u001a\u0004\b\u0019\u0010\u001aR\u001c\u0010\u001b\u001a\u0004\u0018\u00010\tX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\f\"\u0004\b\u001d\u0010\u001eR&\u0010\u0005\u001a\u0004\u0018\u00010\u001f8\u0000@\u0000X\u0081\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b \u0010!\u001a\u0004\b\"\u0010#\"\u0004\b$\u0010%¨\u0006<"}, m5311d2 = {"Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "itemView", "Landroid/view/View;", "(Lcom/drake/brv/BindingAdapter;Landroid/view/View;)V", "viewBinding", "Landroidx/databinding/ViewDataBinding;", "(Lcom/drake/brv/BindingAdapter;Landroidx/databinding/ViewDataBinding;)V", "<set-?>", "", "_data", "get_data", "()Ljava/lang/Object;", "adapter", "Lcom/drake/brv/BindingAdapter;", "getAdapter", "()Lcom/drake/brv/BindingAdapter;", "context", "Landroid/content/Context;", "getContext", "()Landroid/content/Context;", "setContext", "(Landroid/content/Context;)V", "modelPosition", "", "getModelPosition", "()I", "tag", "getTag", "setTag", "(Ljava/lang/Object;)V", "Landroidx/viewbinding/ViewBinding;", "getViewBinding$annotations", "()V", "getViewBinding", "()Landroidx/viewbinding/ViewBinding;", "setViewBinding", "(Landroidx/viewbinding/ViewBinding;)V", "bind", "", "model", "bind$brv_release", "collapse", "depth", "expand", "scrollTop", "", "expandOrCollapse", "findParentPosition", "findParentViewHolder", "findView", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, "id", "(I)Landroid/view/View;", "getBinding", "B", "getBindingOrNull", "getModel", "M", "getModelOrNull", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    public final class BindingViewHolder extends RecyclerView.ViewHolder {

        /* renamed from: a */
        public static final /* synthetic */ int f8925a = 0;

        /* renamed from: b */
        @NotNull
        public Context f8926b;

        /* renamed from: c */
        @NotNull
        public final BindingAdapter f8927c;

        /* renamed from: d */
        public Object f8928d;

        /* renamed from: e */
        @Nullable
        public ViewBinding f8929e;

        /* renamed from: f */
        public final /* synthetic */ BindingAdapter f8930f;

        @Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Landroid/view/View;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
        /* renamed from: com.drake.brv.BindingAdapter$BindingViewHolder$a */
        public static final class C3231a extends Lambda implements Function1<View, Unit> {

            /* renamed from: c */
            public final /* synthetic */ Map.Entry<Integer, Pair<Function2<BindingViewHolder, Integer, Unit>, Boolean>> f8931c;

            /* renamed from: e */
            public final /* synthetic */ BindingAdapter f8932e;

            /* renamed from: f */
            public final /* synthetic */ BindingViewHolder f8933f;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public C3231a(Map.Entry<Integer, Pair<Function2<BindingViewHolder, Integer, Unit>, Boolean>> entry, BindingAdapter bindingAdapter, BindingViewHolder bindingViewHolder) {
                super(1);
                this.f8931c = entry;
                this.f8932e = bindingAdapter;
                this.f8933f = bindingViewHolder;
            }

            @Override // kotlin.jvm.functions.Function1
            public Unit invoke(View view) {
                View throttleClick = view;
                Intrinsics.checkNotNullParameter(throttleClick, "$this$throttleClick");
                Function2<? super BindingViewHolder, ? super Integer, Unit> first = this.f8931c.getValue().getFirst();
                if (first == null) {
                    first = this.f8932e.f8905g;
                }
                if (first != null) {
                    first.invoke(this.f8933f, Integer.valueOf(throttleClick.getId()));
                }
                return Unit.INSTANCE;
            }
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public BindingViewHolder(@NotNull BindingAdapter this$0, View itemView) {
            super(itemView);
            Intrinsics.checkNotNullParameter(this$0, "this$0");
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            this.f8930f = this$0;
            Context context = this$0.f8908j;
            Intrinsics.checkNotNull(context);
            this.f8926b = context;
            this.f8927c = this$0;
            for (final Map.Entry<Integer, Pair<Function2<BindingViewHolder, Integer, Unit>, Boolean>> entry : this$0.f8911m.entrySet()) {
                View findViewById = this.itemView.findViewById(entry.getKey().intValue());
                if (findViewById != null) {
                    if (entry.getValue().getSecond().booleanValue()) {
                        final BindingAdapter bindingAdapter = this.f8930f;
                        findViewById.setOnClickListener(new View.OnClickListener() { // from class: b.i.a.a
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view) {
                                Map.Entry clickListener = entry;
                                BindingAdapter this$02 = bindingAdapter;
                                BindingAdapter.BindingViewHolder this$1 = this;
                                int i2 = BindingAdapter.BindingViewHolder.f8925a;
                                Intrinsics.checkNotNullParameter(clickListener, "$clickListener");
                                Intrinsics.checkNotNullParameter(this$02, "this$0");
                                Intrinsics.checkNotNullParameter(this$1, "this$1");
                                Function2<? super BindingAdapter.BindingViewHolder, ? super Integer, Unit> function2 = (Function2) ((Pair) clickListener.getValue()).getFirst();
                                if (function2 == null) {
                                    function2 = this$02.f8905g;
                                }
                                if (function2 == null) {
                                    return;
                                }
                                function2.invoke(this$1, Integer.valueOf(view.getId()));
                            }
                        });
                    } else {
                        BindingAdapter bindingAdapter2 = this.f8930f;
                        long j2 = bindingAdapter2.f8914p;
                        C3231a block = new C3231a(entry, bindingAdapter2, this);
                        Intrinsics.checkNotNullParameter(findViewById, "<this>");
                        Intrinsics.checkNotNullParameter(block, "block");
                        findViewById.setOnClickListener(new ThrottleClickListener(j2, block));
                    }
                }
            }
            for (final Map.Entry<Integer, Function2<BindingViewHolder, Integer, Unit>> entry2 : this.f8930f.f8912n.entrySet()) {
                View findViewById2 = this.itemView.findViewById(entry2.getKey().intValue());
                if (findViewById2 != null) {
                    final BindingAdapter bindingAdapter3 = this.f8930f;
                    findViewById2.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.i.a.b
                        @Override // android.view.View.OnLongClickListener
                        public final boolean onLongClick(View view) {
                            Map.Entry longClickListener = entry2;
                            BindingAdapter this$02 = bindingAdapter3;
                            BindingAdapter.BindingViewHolder this$1 = this;
                            int i2 = BindingAdapter.BindingViewHolder.f8925a;
                            Intrinsics.checkNotNullParameter(longClickListener, "$longClickListener");
                            Intrinsics.checkNotNullParameter(this$02, "this$0");
                            Intrinsics.checkNotNullParameter(this$1, "this$1");
                            Function2 function2 = (Function2) longClickListener.getValue();
                            if (function2 == null) {
                                BindingAdapter.C3233b c3233b = BindingAdapter.f8897a;
                                Objects.requireNonNull(this$02);
                                function2 = null;
                            }
                            if (function2 == null) {
                                return true;
                            }
                            function2.invoke(this$1, Integer.valueOf(view.getId()));
                            return true;
                        }
                    });
                }
            }
        }

        /* renamed from: a */
        public final <V extends View> V m3941a(@IdRes int i2) {
            return (V) this.itemView.findViewById(i2);
        }

        @NotNull
        /* renamed from: b */
        public final Object m3942b() {
            Object obj = this.f8928d;
            if (obj != null) {
                return obj;
            }
            Intrinsics.throwUninitializedPropertyAccessException("_data");
            return Unit.INSTANCE;
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public BindingViewHolder(@NotNull BindingAdapter this$0, ViewDataBinding viewBinding) {
            super(viewBinding.getRoot());
            Intrinsics.checkNotNullParameter(this$0, "this$0");
            Intrinsics.checkNotNullParameter(viewBinding, "viewBinding");
            this.f8930f = this$0;
            Context context = this$0.f8908j;
            Intrinsics.checkNotNull(context);
            this.f8926b = context;
            this.f8927c = this$0;
            for (final Map.Entry<Integer, Pair<Function2<BindingViewHolder, Integer, Unit>, Boolean>> entry : this$0.f8911m.entrySet()) {
                View findViewById = this.itemView.findViewById(entry.getKey().intValue());
                if (findViewById != null) {
                    if (entry.getValue().getSecond().booleanValue()) {
                        final BindingAdapter bindingAdapter = this.f8930f;
                        findViewById.setOnClickListener(new View.OnClickListener() { // from class: b.i.a.a
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view) {
                                Map.Entry clickListener = entry;
                                BindingAdapter this$02 = bindingAdapter;
                                BindingAdapter.BindingViewHolder this$1 = this;
                                int i2 = BindingAdapter.BindingViewHolder.f8925a;
                                Intrinsics.checkNotNullParameter(clickListener, "$clickListener");
                                Intrinsics.checkNotNullParameter(this$02, "this$0");
                                Intrinsics.checkNotNullParameter(this$1, "this$1");
                                Function2<? super BindingAdapter.BindingViewHolder, ? super Integer, Unit> function2 = (Function2) ((Pair) clickListener.getValue()).getFirst();
                                if (function2 == null) {
                                    function2 = this$02.f8905g;
                                }
                                if (function2 == null) {
                                    return;
                                }
                                function2.invoke(this$1, Integer.valueOf(view.getId()));
                            }
                        });
                    } else {
                        BindingAdapter bindingAdapter2 = this.f8930f;
                        long j2 = bindingAdapter2.f8914p;
                        C3231a block = new C3231a(entry, bindingAdapter2, this);
                        Intrinsics.checkNotNullParameter(findViewById, "<this>");
                        Intrinsics.checkNotNullParameter(block, "block");
                        findViewById.setOnClickListener(new ThrottleClickListener(j2, block));
                    }
                }
            }
            for (final Map.Entry<Integer, Function2<BindingViewHolder, Integer, Unit>> entry2 : this.f8930f.f8912n.entrySet()) {
                View findViewById2 = this.itemView.findViewById(entry2.getKey().intValue());
                if (findViewById2 != null) {
                    final BindingAdapter bindingAdapter3 = this.f8930f;
                    findViewById2.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.i.a.b
                        @Override // android.view.View.OnLongClickListener
                        public final boolean onLongClick(View view) {
                            Map.Entry longClickListener = entry2;
                            BindingAdapter this$02 = bindingAdapter3;
                            BindingAdapter.BindingViewHolder this$1 = this;
                            int i2 = BindingAdapter.BindingViewHolder.f8925a;
                            Intrinsics.checkNotNullParameter(longClickListener, "$longClickListener");
                            Intrinsics.checkNotNullParameter(this$02, "this$0");
                            Intrinsics.checkNotNullParameter(this$1, "this$1");
                            Function2 function2 = (Function2) longClickListener.getValue();
                            if (function2 == null) {
                                BindingAdapter.C3233b c3233b = BindingAdapter.f8897a;
                                Objects.requireNonNull(this$02);
                                function2 = null;
                            }
                            if (function2 == null) {
                                return true;
                            }
                            function2.invoke(this$1, Integer.valueOf(view.getId()));
                            return true;
                        }
                    });
                }
            }
            this.f8929e = viewBinding;
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(BindingViewHolder bindingViewHolder, int i2, List payloads) {
        BindingViewHolder holder = bindingViewHolder;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        super.onBindViewHolder(holder, i2, payloads);
    }
}
