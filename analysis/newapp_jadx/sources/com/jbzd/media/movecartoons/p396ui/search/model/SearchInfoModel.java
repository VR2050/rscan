package com.jbzd.media.movecartoons.p396ui.search.model;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.FilterData;
import com.jbzd.media.movecartoons.bean.response.HotSearch;
import com.jbzd.media.movecartoons.bean.response.HotTagAndCategor;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b3\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u001f\u0010\n\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\f\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u000e\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\u000e\u0010\rJ\u0017\u0010\u000f\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\u000f\u0010\rJI\u0010\u0014\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00062(\b\u0002\u0010\u0013\u001a\"\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0011j\u0010\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u0006\u0018\u0001`\u00122\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\u0014\u0010\u0015J\u001f\u0010\u0016\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\u0016\u0010\u000bR\u0018\u0010\u0018\u001a\u0004\u0018\u00010\u00178\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0018\u0010\u0019R)\u0010!\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u001c0\u001b0\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010 RU\u0010&\u001a:\u00126\u00124\u0012\u0004\u0012\u00020\u0006\u0012\n\u0012\b\u0012\u0004\u0012\u00020#0\"0\u0011j\u001e\u0012\u0004\u0012\u00020\u0006\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020#0\"j\b\u0012\u0004\u0012\u00020#`$`\u00120\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001e\u001a\u0004\b\n\u0010 RY\u0010*\u001a>\u0012\u0004\u0012\u00020\u0006\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020#0\"j\b\u0012\u0004\u0012\u00020#`$0\u0011j\u001e\u0012\u0004\u0012\u00020\u0006\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020#0\"j\b\u0012\u0004\u0012\u00020#`$`\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u001e\u001a\u0004\b(\u0010)R#\u0010.\u001a\b\u0012\u0004\u0012\u00020+0\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u001e\u001a\u0004\b-\u0010 R\u0018\u0010/\u001a\u0004\u0018\u00010\u00178\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u0010\u0019RU\u00102\u001a:\u00126\u00124\u0012\u0004\u0012\u00020\u0006\u0012\n\u0012\b\u0012\u0004\u0012\u00020#0\"0\u0011j\u001e\u0012\u0004\u0012\u00020\u0006\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020#0\"j\b\u0012\u0004\u0012\u00020#`$`\u00120\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u001e\u001a\u0004\b1\u0010 ¨\u00064"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "position", "", "hasLoading", "getLibrary", "(Ljava/lang/String;Z)V", "postFilter", "(Z)V", "comicsFilter", "novelFilter", "type", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "map", "getKeywords", "(Ljava/lang/String;Ljava/util/HashMap;Z)V", "getPostCategories", "Lc/a/d1;", "libraryJob", "Lc/a/d1;", "Landroidx/lifecycle/MutableLiveData;", "", "Lcom/jbzd/media/movecartoons/bean/response/HotTagAndCategor;", "hotTagAndCategor$delegate", "Lkotlin/Lazy;", "getHotTagAndCategor", "()Landroidx/lifecycle/MutableLiveData;", "hotTagAndCategor", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/FilterData;", "Lkotlin/collections/ArrayList;", "library$delegate", "library", "listMap$delegate", "getListMap", "()Ljava/util/HashMap;", "listMap", "Lcom/jbzd/media/movecartoons/bean/response/HotSearch;", "hotKeywords$delegate", "getHotKeywords", "hotKeywords", "hotJob", "filterData$delegate", "getFilterData", "filterData", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchInfoModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 hotJob;

    @Nullable
    private InterfaceC3053d1 libraryJob;

    /* renamed from: hotKeywords$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy hotKeywords = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<HotSearch>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$hotKeywords$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<HotSearch> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: hotTagAndCategor$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy hotTagAndCategor = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends HotTagAndCategor>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$hotTagAndCategor$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends HotTagAndCategor>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: listMap$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy listMap = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, ArrayList<FilterData>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$listMap$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, ArrayList<FilterData>> invoke() {
            return new HashMap<>();
        }
    });

    /* renamed from: library$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy library = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<HashMap<String, ArrayList<FilterData>>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$library$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: filterData$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy filterData = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<HashMap<String, ArrayList<FilterData>>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$filterData$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> invoke() {
            return new MutableLiveData<>();
        }
    });

    public static /* synthetic */ void comicsFilter$default(SearchInfoModel searchInfoModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        searchInfoModel.comicsFilter(z);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void getKeywords$default(SearchInfoModel searchInfoModel, String str, HashMap hashMap, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            hashMap = null;
        }
        if ((i2 & 4) != 0) {
            z = true;
        }
        searchInfoModel.getKeywords(str, hashMap, z);
    }

    public static /* synthetic */ void getLibrary$default(SearchInfoModel searchInfoModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        searchInfoModel.getLibrary(str, z);
    }

    public static /* synthetic */ void getPostCategories$default(SearchInfoModel searchInfoModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        searchInfoModel.getPostCategories(str, z);
    }

    public static /* synthetic */ void novelFilter$default(SearchInfoModel searchInfoModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        searchInfoModel.novelFilter(z);
    }

    public static /* synthetic */ void postFilter$default(SearchInfoModel searchInfoModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        searchInfoModel.postFilter(z);
    }

    public final void comicsFilter(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.libraryJob = C0917a.m221e(C0917a.f372a, "comics/filter", String.class, new HashMap(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$comicsFilter$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getFilterData().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$comicsFilter$2
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> getFilterData() {
        return (MutableLiveData) this.filterData.getValue();
    }

    @NotNull
    public final MutableLiveData<HotSearch> getHotKeywords() {
        return (MutableLiveData) this.hotKeywords.getValue();
    }

    @NotNull
    public final MutableLiveData<List<HotTagAndCategor>> getHotTagAndCategor() {
        return (MutableLiveData) this.hotTagAndCategor.getValue();
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0040, code lost:
    
        if (r20.equals("cartoon") == false) goto L21;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void getKeywords(@org.jetbrains.annotations.NotNull java.lang.String r20, @org.jetbrains.annotations.Nullable java.util.HashMap<java.lang.String, java.lang.String> r21, final boolean r22) {
        /*
            r19 = this;
            r0 = r19
            r1 = r20
            r2 = r21
            r3 = r22
            java.lang.String r4 = "type"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r4)
            if (r3 == 0) goto L22
            androidx.lifecycle.MutableLiveData r4 = r19.getLoading()
            b.w.b.b.f.a r11 = new b.w.b.b.f.a
            r6 = 1
            r7 = 0
            r8 = 0
            r9 = 0
            r10 = 14
            r5 = r11
            r5.<init>(r6, r7, r8, r9, r10)
            r4.setValue(r11)
        L22:
            int r4 = r20.hashCode()
            r5 = -1354819208(0xffffffffaf3f1978, float:-1.7380397E-10)
            java.lang.String r6 = "comics"
            java.lang.String r7 = "movie/keywords"
            if (r4 == r5) goto L4f
            r5 = 105010748(0x642563c, float:3.65507E-35)
            if (r4 == r5) goto L43
            r5 = 554426222(0x210bdf6e, float:4.739074E-19)
            if (r4 == r5) goto L3a
            goto L55
        L3a:
            java.lang.String r4 = "cartoon"
            boolean r4 = r1.equals(r4)
            if (r4 != 0) goto L68
            goto L55
        L43:
            java.lang.String r4 = "novel"
            boolean r4 = r1.equals(r4)
            if (r4 != 0) goto L4c
            goto L55
        L4c:
            java.lang.String r7 = "novel/keywords"
            goto L68
        L4f:
            boolean r4 = r1.equals(r6)
            if (r4 != 0) goto L66
        L55:
            if (r2 != 0) goto L58
            goto L5b
        L58:
            r21.clone()
        L5b:
            if (r2 != 0) goto L5e
            goto L68
        L5e:
            java.lang.String r4 = "position"
            java.lang.String r5 = "normal"
            r2.put(r4, r5)
            goto L68
        L66:
            java.lang.String r7 = "comics/keywords"
        L68:
            r9 = r7
            boolean r1 = kotlin.jvm.internal.Intrinsics.areEqual(r1, r6)
            if (r1 == 0) goto L72
            r1 = 0
            r11 = r1
            goto L73
        L72:
            r11 = r2
        L73:
            java.lang.Class<com.jbzd.media.movecartoons.bean.response.HotSearch> r10 = com.jbzd.media.movecartoons.bean.response.HotSearch.class
            b.a.a.a.r.a r8 = p005b.p006a.p007a.p008a.p017r.C0917a.f372a
            com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getKeywords$1 r12 = new com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getKeywords$1
            r12.<init>()
            com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getKeywords$2 r13 = new com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getKeywords$2
            r13.<init>()
            r14 = 0
            r15 = 0
            r16 = 0
            r17 = 0
            r18 = 480(0x1e0, float:6.73E-43)
            c.a.d1 r1 = p005b.p006a.p007a.p008a.p017r.C0917a.m221e(r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18)
            r0.hotJob = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.search.model.SearchInfoModel.getKeywords(java.lang.String, java.util.HashMap, boolean):void");
    }

    @NotNull
    public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> getLibrary() {
        return (MutableLiveData) this.library.getValue();
    }

    @NotNull
    public final HashMap<String, ArrayList<FilterData>> getListMap() {
        return (HashMap) this.listMap.getValue();
    }

    public final void getPostCategories(@NotNull String position, boolean hasLoading) {
        Intrinsics.checkNotNullParameter(position, "position");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap m595Q = C1499a.m595Q("position", position);
        Unit unit = Unit.INSTANCE;
        this.hotJob = C0917a.m222f(C0917a.f372a, "post/categories", HotTagAndCategor.class, m595Q, new Function1<List<? extends HotTagAndCategor>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getPostCategories$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends HotTagAndCategor> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends HotTagAndCategor> list) {
                SearchInfoModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                SearchInfoModel.this.getHotTagAndCategor().setValue(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getPostCategories$3
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
                SearchInfoModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                C2354n.m2449Z(it.getMessage());
            }
        }, false, false, null, false, 480);
    }

    public final void novelFilter(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.libraryJob = C0917a.m221e(C0917a.f372a, "novel/filter", String.class, new HashMap(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$novelFilter$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getFilterData().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$novelFilter$2
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.hotJob, this.libraryJob);
    }

    public final void postFilter(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        new HashMap().put("position", "normal");
        this.libraryJob = C0917a.m221e(C0917a.f372a, "post/filter", String.class, new HashMap(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$postFilter$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getFilterData().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$postFilter$2
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void getLibrary(@NotNull String position, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(position, "position");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("position", position);
        this.libraryJob = C0917a.m221e(C0917a.f372a, "movie/filter", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getLibrary$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getLibrary().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchInfoModel$getLibrary$2
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }
}
