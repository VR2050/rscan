package com.jbzd.media.movecartoons.p396ui.index.medialib.child;

import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.media.MediaPlayer;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.ProgressBar;
import androidx.exifinterface.media.ExifInterface;
import androidx.fragment.app.FragmentActivity;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.event.EventUpload;
import com.jbzd.media.movecartoons.bean.response.UploadBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.greendao.UploadBeanDao;
import com.jbzd.media.movecartoons.p396ui.dialog.HistoryBottomDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.lang.ref.WeakReference;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingQueue;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Typography;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0857l0;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p016q.C0911a;
import p005b.p006a.p007a.p008a.p016q.C0914d;
import p005b.p006a.p007a.p008a.p016q.C0916f;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;
import p476m.p496b.p500b.AbstractC4926a;
import p476m.p496b.p500b.C4928c;
import p476m.p496b.p500b.C4930e;
import p476m.p496b.p500b.p503h.C4942a;
import p476m.p496b.p500b.p503h.C4945d;
import p476m.p496b.p500b.p504i.AbstractC4947a;
import p476m.p496b.p500b.p504i.C4950d;
import p476m.p496b.p500b.p504i.C4951e;
import p476m.p496b.p500b.p504i.InterfaceC4952f;

@Deprecated(message = "has no this page!!")
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0007\u0018\u0000 '2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001'B\u0007¢\u0006\u0004\b&\u0010\nJ!\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000b\u0010\nJ\u0017\u0010\u000e\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\fH\u0007¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u001f\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0015\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0018\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0018\u0010\nJ3\u0010\u001e\u001a\u00020\u00062\u0012\u0010\u001a\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00130\u00192\u0006\u0010\u001c\u001a\u00020\u001b2\u0006\u0010\u001d\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\u0006H\u0016¢\u0006\u0004\b \u0010\nJ\u000f\u0010!\u001a\u00020\u0004H\u0016¢\u0006\u0004\b!\u0010\"J\u0011\u0010$\u001a\u0004\u0018\u00010#H\u0016¢\u0006\u0004\b$\u0010%¨\u0006("}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/UploadVideosFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/UploadBean;", "uploadBean", "", "showLoading", "", "publish", "(Lcom/jbzd/media/movecartoons/bean/response/UploadBean;Z)V", "onStart", "()V", "onDestroyView", "Lcom/jbzd/media/movecartoons/bean/event/EventUpload;", "eventUpload", "onEventUpload", "(Lcom/jbzd/media/movecartoons/bean/event/EventUpload;)V", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/UploadBean;)V", "registerItemChildEvent", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemChildClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "initViews", "getLoadMoreEnable", "()Z", "Lc/a/d1;", "request", "()Lc/a/d1;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UploadVideosFragment extends BaseListFragment<UploadBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/UploadVideosFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/medialib/child/UploadVideosFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/medialib/child/UploadVideosFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final UploadVideosFragment newInstance() {
            return new UploadVideosFragment();
        }
    }

    private final void publish(final UploadBean uploadBean, boolean showLoading) {
        if (showLoading) {
            showLoadingDialog("发布中...", true);
        }
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        String str = uploadBean.title;
        if (str == null) {
            str = "";
        }
        hashMap.put(VideoListActivity.KEY_TITLE, str);
        String str2 = uploadBean.img;
        if (str2 == null) {
            str2 = "";
        }
        hashMap.put("img", str2);
        String str3 = uploadBean.point;
        if (str3 == null) {
            str3 = "";
        }
        hashMap.put(VideoTypeBean.video_type_point, str3);
        String str4 = uploadBean.tag_id;
        if (str4 == null) {
            str4 = "";
        }
        hashMap.put("tag_id", str4);
        String str5 = uploadBean.link;
        if (str5 == null) {
            str5 = "";
        }
        hashMap.put("link", str5);
        String str6 = uploadBean.duration;
        if (str6 == null) {
            str6 = "";
        }
        hashMap.put("duration", str6);
        String str7 = uploadBean.canvas;
        hashMap.put("canvas", str7 != null ? str7 : "");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "save/works", Object.class, hashMap, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.UploadVideosFragment$publish$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
                UploadVideosFragment.this.hideLoadingDialog();
                C2354n.m2409L1("发布成功,请到作品管理中查看");
                uploadBean.status = UploadBean.PUBLISHED;
                C4909c.m5569b().m5574g(new EventUpload(uploadBean));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.UploadVideosFragment$publish$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                UploadVideosFragment.this.hideLoadingDialog();
                uploadBean.status = UploadBean.PUBLISH_ERROR;
                C4909c.m5569b().m5574g(new EventUpload(uploadBean));
            }
        }, false, false, null, false, 480);
    }

    public static /* synthetic */ void publish$default(UploadVideosFragment uploadVideosFragment, UploadBean uploadBean, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = false;
        }
        uploadVideosFragment.publish(uploadBean, z);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_upload;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getLoadMoreEnable() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getMSwipeLayout().setEnabled(false);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        C4909c.m5569b().m5580m(this);
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onEventUpload(@NotNull EventUpload eventUpload) {
        Intrinsics.checkNotNullParameter(eventUpload, "eventUpload");
        UploadBean uploadVideoInfo = eventUpload.getUploadVideoInfo();
        Iterator<UploadBean> it = getAdapter().getData().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (Intrinsics.areEqual(it.next().getIdStr(), uploadVideoInfo.getIdStr())) {
                UploadBean uploadBean = getAdapter().getData().get(i2);
                uploadBean.status = uploadVideoInfo.status;
                uploadBean.progress_slice = uploadVideoInfo.progress_slice;
                uploadBean.total_slices = uploadVideoInfo.total_slices;
                String str = uploadVideoInfo.status;
                if (Intrinsics.areEqual(str, UploadBean.PUBLISHED)) {
                    getAdapter().remove(i2);
                    Intrinsics.checkNotNullExpressionValue(uploadVideoInfo, "uploadVideoInfo");
                    C0916f.m218a(uploadVideoInfo);
                    return;
                } else {
                    if (!Intrinsics.areEqual(str, "completed")) {
                        getAdapter().notifyItemChanged(i2);
                        return;
                    }
                    Intrinsics.checkNotNullExpressionValue(uploadVideoInfo, "uploadVideoInfo");
                    publish$default(this, uploadVideoInfo, false, 2, null);
                    getAdapter().notifyItemChanged(i2);
                    return;
                }
            }
            i2 = i3;
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemChildClick(@NotNull final BaseQuickAdapter<UploadBean, BaseViewHolder> adapter, @NotNull View view, final int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemChildClick(adapter, view, position);
        final UploadBean uploadBean = adapter.getData().get(position);
        if (view.getId() == R.id.tv_more) {
            new HistoryBottomDialog("删除", new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.UploadVideosFragment$onItemChildClick$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    C0916f.m218a(UploadBean.this);
                    adapter.remove(position);
                    C0857l0 c0857l0 = C0857l0.f275a;
                    C0857l0 c0857l02 = C0857l0.f276b;
                    String idStr = UploadBean.this.getIdStr();
                    Intrinsics.checkNotNullExpressionValue(idStr, "item.idStr");
                    int i2 = 0;
                    String[] taskIds = {idStr};
                    Objects.requireNonNull(c0857l02);
                    Intrinsics.checkNotNullParameter(taskIds, "taskIds");
                    while (i2 < 1) {
                        String str = taskIds[i2];
                        i2++;
                        Iterator it = ((LinkedBlockingQueue) c0857l02.f279e.getValue()).iterator();
                        while (it.hasNext()) {
                            UploadBean uploadBean2 = (UploadBean) it.next();
                            if (Intrinsics.areEqual(uploadBean2.getIdStr(), str)) {
                                ((LinkedBlockingQueue) c0857l02.f279e.getValue()).remove(uploadBean2);
                            }
                        }
                    }
                }
            }).show(getChildFragmentManager(), "UploadListBottomDialogItem");
            return;
        }
        if (view.getId() == R.id.tv_edit) {
            if (TextUtils.equals(uploadBean.status, UploadBean.PUBLISH_ERROR) || TextUtils.equals(uploadBean.status, "completed")) {
                publish(uploadBean, true);
                return;
            }
            FragmentActivity activity = getActivity();
            if (activity == null) {
                return;
            }
            activity.onBackPressed();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.tv_more, R.id.tv_edit);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        AbstractC4947a abstractC4947a;
        boolean z;
        C0914d c0914d = C0911a.f369a;
        if (c0914d == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mDaoSession");
            throw null;
        }
        AbstractC4926a<?, ?> m5603a = c0914d.m5603a(UploadBean.class);
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        C4930e[] c4930eArr = {UploadBeanDao.Properties.Time};
        StringBuilder sb = null;
        for (int i2 = 0; i2 < 1; i2++) {
            C4930e c4930e = c4930eArr[i2];
            if (sb == null) {
                sb = new StringBuilder();
            } else if (sb.length() > 0) {
                sb.append(ChineseToPinyinResource.Field.COMMA);
            }
            C4930e[] c4930eArr2 = m5603a.f12572a.f12598f;
            int length = c4930eArr2.length;
            int i3 = 0;
            while (true) {
                if (i3 >= length) {
                    z = false;
                    break;
                }
                if (c4930e == c4930eArr2[i3]) {
                    z = true;
                    break;
                }
                i3++;
            }
            if (!z) {
                StringBuilder m586H = C1499a.m586H("Property '");
                m586H.append(c4930e.f12582c);
                m586H.append("' is not part of ");
                m586H.append(m5603a);
                throw new C4928c(m586H.toString());
            }
            sb.append(ExifInterface.GPS_DIRECTION_TRUE);
            sb.append('.');
            sb.append('\'');
            sb.append(c4930e.f12584e);
            sb.append('\'');
            if (String.class.equals(c4930e.f12581b)) {
                sb.append(" COLLATE NOCASE");
            }
            sb.append(" DESC");
        }
        C4942a c4942a = m5603a.f12572a;
        String str = c4942a.f12597e;
        String[] strArr = c4942a.f12599g;
        int i4 = C4945d.f12616a;
        StringBuilder sb2 = new StringBuilder("SELECT ");
        int length2 = strArr.length;
        for (int i5 = 0; i5 < length2; i5++) {
            String str2 = strArr[i5];
            sb2.append(ExifInterface.GPS_DIRECTION_TRUE);
            sb2.append(".\"");
            sb2.append(str2);
            sb2.append(Typography.quote);
            if (i5 < length2 - 1) {
                sb2.append(',');
            }
        }
        sb2.append(" FROM ");
        sb2.append(Typography.quote);
        sb2.append(str);
        sb2.append(Typography.quote);
        sb2.append(' ');
        sb2.append(ExifInterface.GPS_DIRECTION_TRUE);
        sb2.append(' ');
        StringBuilder sb3 = new StringBuilder(sb2.toString());
        arrayList.clear();
        Iterator it = arrayList2.iterator();
        if (it.hasNext()) {
            C4950d c4950d = (C4950d) it.next();
            sb3.append(" JOIN ");
            sb3.append(Typography.quote);
            Objects.requireNonNull(c4950d);
            throw null;
        }
        if (!arrayList3.isEmpty()) {
            sb3.append(" WHERE ");
            ListIterator listIterator = arrayList3.listIterator();
            while (listIterator.hasNext()) {
                if (listIterator.hasPrevious()) {
                    sb3.append(" AND ");
                }
                InterfaceC4952f interfaceC4952f = (InterfaceC4952f) listIterator.next();
                interfaceC4952f.m5617b(sb3, ExifInterface.GPS_DIRECTION_TRUE);
                interfaceC4952f.m5616a(arrayList);
            }
        }
        Iterator it2 = arrayList2.iterator();
        if (it2.hasNext()) {
            Objects.requireNonNull((C4950d) it2.next());
            throw null;
        }
        if (sb != null && sb.length() > 0) {
            sb3.append(" ORDER BY ");
            sb3.append((CharSequence) sb);
        }
        String sb4 = sb3.toString();
        Object[] array = arrayList.toArray();
        int length3 = array.length;
        String[] strArr2 = new String[length3];
        for (int i6 = 0; i6 < length3; i6++) {
            Object obj = array[i6];
            if (obj != null) {
                strArr2[i6] = obj.toString();
            } else {
                strArr2[i6] = null;
            }
        }
        C4951e.b bVar = new C4951e.b(m5603a, sb4, strArr2, -1, -1);
        long id = Thread.currentThread().getId();
        synchronized (bVar.f12629d) {
            try {
                WeakReference weakReference = (WeakReference) bVar.f12629d.get(Long.valueOf(id));
                abstractC4947a = weakReference != null ? (AbstractC4947a) weakReference.get() : null;
                if (abstractC4947a == null) {
                    bVar.m5615a();
                    C4951e c4951e = new C4951e(bVar, m5603a, sb4, (String[]) strArr2.clone(), bVar.f12630e, bVar.f12631f, null);
                    bVar.f12629d.put(Long.valueOf(id), new WeakReference(c4951e));
                    abstractC4947a = c4951e;
                } else {
                    System.arraycopy(strArr2, 0, abstractC4947a.f12624d, 0, length3);
                }
            } catch (Throwable th) {
                th = th;
                while (true) {
                    try {
                        throw th;
                    } catch (Throwable th2) {
                        th = th2;
                    }
                }
            }
        }
        C4951e c4951e2 = (C4951e) abstractC4947a;
        if (Thread.currentThread() != c4951e2.f12625e) {
            throw new C4928c("Method may be called only in owner thread, use forCurrentThread to get an instance for this thread");
        }
        Cursor mo5605b = c4951e2.f12621a.f12573b.mo5605b(c4951e2.f12623c, c4951e2.f12624d);
        AbstractC4926a<T, ?> abstractC4926a = c4951e2.f12622b.f12579a;
        Objects.requireNonNull(abstractC4926a);
        try {
            List m5600d = abstractC4926a.m5600d(mo5605b);
            mo5605b.close();
            Intrinsics.checkNotNullExpressionValue(m5600d, "DBManager.mDaoSession.queryBuilder(UploadBean::class.java).orderDesc(UploadBeanDao.Properties.Time).list()");
            didRequestComplete(m5600d);
            return null;
        } catch (Throwable th3) {
            mo5605b.close();
            throw th3;
        }
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull UploadBean item) {
        Bitmap bitmap;
        int i2;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        ImageView view = (ImageView) helper.m3912b(R.id.iv_img);
        if (item.isLong()) {
            view.setScaleType(ImageView.ScaleType.CENTER_CROP);
        } else {
            view.setScaleType(ImageView.ScaleType.FIT_CENTER);
        }
        if (!TextUtils.isEmpty(item.img_show)) {
            C2852c m2463c2 = C2354n.m2463c2(this);
            String str = item.img_show;
            if (str == null) {
                str = "";
            }
            C1558h mo770c = m2463c2.mo770c();
            mo770c.mo763X(str);
            ((C2851b) mo770c).m3295i0().m757R(view);
        } else {
            C2852c m2463c22 = C2354n.m2463c2(this);
            Objects.requireNonNull(m2463c22);
            m2463c22.m772e(new ComponentCallbacks2C1559i.b(view));
            try {
                bitmap = BitmapFactory.decodeFile(item.image_path);
            } catch (Exception e2) {
                e2.printStackTrace();
                bitmap = null;
            }
            view.setImageBitmap(bitmap);
        }
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(5.0d));
        view.setClipToOutline(true);
        String str2 = item.video_path;
        try {
            MediaPlayer mediaPlayer = new MediaPlayer();
            mediaPlayer.setDataSource(str2);
            mediaPlayer.prepare();
            i2 = mediaPlayer.getDuration();
            mediaPlayer.release();
        } catch (Exception unused) {
            i2 = 0;
        }
        int i3 = i2 / 1000;
        int i4 = i3 / 3600;
        int i5 = (i3 % 3600) / 60;
        int i6 = i3 % 60;
        String str3 = (i5 < 10 ? Intrinsics.stringPlus("0", Integer.valueOf(i5)) : String.valueOf(i5)) + ':' + (i6 < 10 ? Intrinsics.stringPlus("0", Integer.valueOf(i6)) : String.valueOf(i6));
        if (i4 != 0) {
            str3 = i4 + ':' + str3;
        }
        helper.m3919i(R.id.itv_duration, str3);
        CharSequence charSequence = item.title;
        if (charSequence == null) {
            charSequence = "";
        }
        helper.m3919i(R.id.tv_name, charSequence);
        CharSequence format = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date(item.time));
        Intrinsics.checkNotNullExpressionValue(format, "format.format(d1)");
        helper.m3919i(R.id.tv_time, format);
        CharSequence charSequence2 = item.point;
        if (charSequence2 == null) {
            charSequence2 = "";
        }
        helper.m3919i(R.id.itv_price, charSequence2);
        helper.m3916f(R.id.rl_price, !item.getIsMoneyVideo());
        helper.m3916f(R.id.tv_freeFlag, true);
        if (item.is_draft) {
            helper.m3916f(R.id.tv_edit, false);
            helper.m3922l(R.id.ll_progress, false);
            helper.m3919i(R.id.tv_tips, "草稿");
            return;
        }
        String str4 = item.status;
        if (str4 != null) {
            switch (str4.hashCode()) {
                case -1951561000:
                    if (str4.equals(UploadBean.PUBLISH_ERROR)) {
                        helper.m3916f(R.id.tv_edit, false);
                        helper.m3922l(R.id.ll_progress, false);
                        helper.m3919i(R.id.tv_tips, "发布失败");
                        helper.m3919i(R.id.tv_edit, "重新发布");
                        return;
                    }
                    break;
                case -1402931637:
                    if (str4.equals("completed")) {
                        helper.m3916f(R.id.tv_edit, false);
                        helper.m3922l(R.id.ll_progress, false);
                        helper.m3919i(R.id.tv_tips, "已上传");
                        helper.m3919i(R.id.tv_edit, "发布");
                        return;
                    }
                    break;
                case 3641717:
                    if (str4.equals("wait")) {
                        helper.m3916f(R.id.tv_edit, true);
                        helper.m3922l(R.id.ll_progress, false);
                        helper.m3919i(R.id.tv_tips, "等待上传");
                        helper.m3919i(R.id.tv_edit, "");
                        return;
                    }
                    break;
                case 95763319:
                    if (str4.equals("doing")) {
                        helper.m3916f(R.id.tv_edit, true);
                        helper.m3922l(R.id.ll_progress, true);
                        helper.m3919i(R.id.tv_tips, "");
                        int i7 = (item.progress_slice * 100) / item.total_slices;
                        ((ProgressBar) helper.m3912b(R.id.pb_progress)).setProgress(i7);
                        StringBuilder sb = new StringBuilder();
                        sb.append(i7);
                        sb.append('%');
                        helper.m3919i(R.id.tv_progress, sb.toString());
                        helper.m3919i(R.id.tv_edit, "");
                        return;
                    }
                    break;
                case 96784904:
                    if (str4.equals("error")) {
                        helper.m3916f(R.id.tv_edit, false);
                        helper.m3922l(R.id.ll_progress, false);
                        helper.m3919i(R.id.tv_tips, "上传失败");
                        helper.m3919i(R.id.tv_edit, "编辑");
                        return;
                    }
                    break;
                case 1447404014:
                    if (str4.equals(UploadBean.PUBLISHED)) {
                        helper.m3916f(R.id.tv_edit, false);
                        helper.m3922l(R.id.ll_progress, false);
                        helper.m3919i(R.id.tv_tips, "已发布");
                        helper.m3919i(R.id.tv_edit, "");
                        return;
                    }
                    break;
            }
        }
        helper.m3916f(R.id.tv_edit, false);
        helper.m3922l(R.id.ll_progress, false);
        helper.m3919i(R.id.tv_tips, "上传失败");
        helper.m3919i(R.id.tv_edit, "编辑");
    }
}
