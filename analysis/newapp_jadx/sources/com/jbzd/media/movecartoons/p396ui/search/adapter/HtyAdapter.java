package com.jbzd.media.movecartoons.p396ui.search.adapter;

import android.content.SharedPreferences;
import android.view.View;
import android.widget.TextView;
import com.alibaba.fastjson.JSON;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0841d0;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010!\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B!\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0010\b\u0002\u0010\f\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u000b¢\u0006\u0004\b\r\u0010\u000eJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/adapter/HtyAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/String;)V", "", "layoutResId", "", "data", "<init>", "(ILjava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HtyAdapter extends BaseQuickAdapter<String, BaseViewHolder> {
    public /* synthetic */ HtyAdapter(int i2, List list, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(i2, (i3 & 2) != 0 ? null : list);
    }

    public HtyAdapter(int i2, @Nullable List<String> list) {
        super(i2, list);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull final String item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        helper.m3919i(R.id.tv_content, item);
        TextView textView = (TextView) helper.m3912b(R.id.tv_delet);
        final Function1<TextView, Unit> block = new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.adapter.HtyAdapter$convert$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                String rm = item;
                Intrinsics.checkNotNullParameter(rm, "rm");
                if (C0841d0.f236a == null) {
                    if (C0841d0.f236a == null) {
                        Intrinsics.checkNotNullParameter("history", "key");
                        Intrinsics.checkNotNullParameter("[]", "default");
                        ApplicationC2828a applicationC2828a = C2827a.f7670a;
                        if (applicationC2828a == null) {
                            Intrinsics.throwUninitializedPropertyAccessException("context");
                            throw null;
                        }
                        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
                        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                        String string = sharedPreferences.getString("history", "[]");
                        Intrinsics.checkNotNull(string);
                        List parseArray = JSON.parseArray(string, String.class);
                        Objects.requireNonNull(parseArray, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
                        C0841d0.f236a = TypeIntrinsics.asMutableList(parseArray);
                    }
                    List<String> list = C0841d0.f236a;
                    Objects.requireNonNull(list, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
                    TypeIntrinsics.asMutableList(list);
                }
                List<String> list2 = C0841d0.f236a;
                if (list2 != null) {
                    list2.remove(rm);
                }
                String value = JSON.toJSONString(C0841d0.f236a);
                Intrinsics.checkNotNullExpressionValue(value, "toJSONString(historyItems)");
                Intrinsics.checkNotNullParameter("history", "key");
                Intrinsics.checkNotNullParameter(value, "value");
                ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
                if (applicationC2828a2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                SharedPreferences sharedPreferences2 = applicationC2828a2.getSharedPreferences("default_storage", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                SharedPreferences.Editor editor = sharedPreferences2.edit();
                Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
                editor.putString("history", value);
                editor.commit();
                this.notifyDataSetChanged();
            }
        };
        Intrinsics.checkNotNullParameter(textView, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.a.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                Function1 block2 = Function1.this;
                Intrinsics.checkNotNullParameter(block2, "$block");
                Objects.requireNonNull(view, "null cannot be cast to non-null type T of com.jbzd.media.movecartoons.utils.ViewClickDelayKt.click$lambda-0");
                block2.invoke(view);
            }
        });
    }
}
