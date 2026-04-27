package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.LanguageCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sliding.SlidingLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Timer;
import java.util.TimerTask;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryLanguageSelectActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private EmptyTextProgressView emptyView;
    private int item_done = 1;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private Context mContext;
    private SlidingLayout root;
    private ListAdapter searchListViewAdapter;
    private ArrayList<LocaleController.LocaleInfo> searchResult;
    private Timer searchTimer;
    private boolean searchWas;
    private boolean searching;
    private LocaleController.LocaleInfo selectedLanguage;
    private ArrayList<LocaleController.LocaleInfo> sortedLanguages;
    private ArrayList<LocaleController.LocaleInfo> unofficialLanguages;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        fillLanguages();
        LocaleController.getInstance().loadRemoteLanguages(this.currentAccount);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.suggestedLangpack);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.suggestedLangpack);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        return (MrySearchView) this.fragmentView.findViewById(R.attr.searchview);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.searching = false;
        this.searchWas = false;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_list_search_frame_layout, (ViewGroup) null, false);
        this.selectedLanguage = LocaleController.getInstance().getCurrentLocaleInfo();
        initActionBar();
        super.createView(context);
        SlidingLayout slidingLayout = (SlidingLayout) this.fragmentView;
        this.root = slidingLayout;
        slidingLayout.setFollowView(this.searchView);
        initList();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("LanguageSetting", R.string.LanguageSetting));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.MryLanguageSelectActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id != -1) {
                    if (id == MryLanguageSelectActivity.this.item_done) {
                        if (MryLanguageSelectActivity.this.selectedLanguage != null) {
                            LocaleController.getInstance().applyLanguage(MryLanguageSelectActivity.this.selectedLanguage, true, false, false, true, MryLanguageSelectActivity.this.currentAccount);
                            MryLanguageSelectActivity.this.parentLayout.rebuildAllFragmentViews(false, false);
                        }
                        MryLanguageSelectActivity.this.finishFragment();
                        return;
                    }
                    return;
                }
                MryLanguageSelectActivity.this.finishFragment();
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(this.item_done, LocaleController.getString("Done", R.string.Done));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected void initSearchView() {
        super.initSearchView();
        this.searchView.setHintText(LocaleController.getString("Search", R.string.Search));
    }

    private void initList() {
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.listView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listview);
        EmptyTextProgressView emptyTextProgressView = (EmptyTextProgressView) this.fragmentView.findViewById(R.attr.emptyTextProgress);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setText(LocaleController.getString("NoResult", R.string.NoResult));
        this.emptyView.showTextView();
        this.emptyView.setShowAtCenter(true);
        this.listView.setEmptyView(this.emptyView);
        this.listView.setLayoutManager(new LinearLayoutManager(this.mContext, 1, false));
        this.listView.setVerticalScrollBarEnabled(false);
        this.listAdapter = new ListAdapter(this.mContext, false);
        this.searchListViewAdapter = new ListAdapter(this.mContext, true);
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryLanguageSelectActivity$vuFcSImNxTnjF8PzipT43TGtls4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$0$MryLanguageSelectActivity(view, i);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryLanguageSelectActivity$8HRjxmEHkS7k3_yI9ajeP0wvqQ4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i) {
                return this.f$0.lambda$initList$2$MryLanguageSelectActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.MryLanguageSelectActivity.2
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && MryLanguageSelectActivity.this.searching && MryLanguageSelectActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(MryLanguageSelectActivity.this.getParentActivity().getCurrentFocus());
                }
            }
        });
    }

    public /* synthetic */ void lambda$initList$0$MryLanguageSelectActivity(View view, int position) {
        if (view instanceof LanguageCell) {
            LanguageCell cell = (LanguageCell) view;
            this.selectedLanguage = cell.getCurrentLocale();
            this.listAdapter.notifyDataSetChanged();
        }
    }

    public /* synthetic */ boolean lambda$initList$2$MryLanguageSelectActivity(View view, int position) {
        if (getParentActivity() == null || this.parentLayout == null || !(view instanceof LanguageCell)) {
            return false;
        }
        LanguageCell cell = (LanguageCell) view;
        final LocaleController.LocaleInfo localeInfo = cell.getCurrentLocale();
        if (localeInfo == null || localeInfo.pathToFile == null || (localeInfo.isRemote() && localeInfo.serverIndex != Integer.MAX_VALUE)) {
            return false;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setMessage(LocaleController.getString("DeleteLocalization", R.string.DeleteLocalization));
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryLanguageSelectActivity$lldQVvz7AYsqH0GCQ73M5g1tK4U
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$1$MryLanguageSelectActivity(localeInfo, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
        return true;
    }

    public /* synthetic */ void lambda$null$1$MryLanguageSelectActivity(LocaleController.LocaleInfo finalLocaleInfo, DialogInterface dialogInterface, int i) {
        if (LocaleController.getInstance().deleteLanguage(finalLocaleInfo, this.currentAccount)) {
            fillLanguages();
            ArrayList<LocaleController.LocaleInfo> arrayList = this.searchResult;
            if (arrayList != null) {
                arrayList.remove(finalLocaleInfo);
            }
            ListAdapter listAdapter = this.listAdapter;
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
            ListAdapter listAdapter2 = this.searchListViewAdapter;
            if (listAdapter2 != null) {
                listAdapter2.notifyDataSetChanged();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.suggestedLangpack && this.listAdapter != null) {
            fillLanguages();
            this.listAdapter.notifyDataSetChanged();
        }
    }

    private void fillLanguages() {
        final LocaleController.LocaleInfo currentLocale = LocaleController.getInstance().getCurrentLocaleInfo();
        Comparator<LocaleController.LocaleInfo> comparator = new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryLanguageSelectActivity$RomRZCW9QML4gthrwwgBtVF2OdE
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MryLanguageSelectActivity.lambda$fillLanguages$3(currentLocale, (LocaleController.LocaleInfo) obj, (LocaleController.LocaleInfo) obj2);
            }
        };
        this.sortedLanguages = new ArrayList<>();
        this.unofficialLanguages = new ArrayList<>(LocaleController.getInstance().unofficialLanguages);
        ArrayList<LocaleController.LocaleInfo> arrayList = LocaleController.getInstance().languages;
        int size = arrayList.size();
        for (int a = 0; a < size; a++) {
            LocaleController.LocaleInfo info = arrayList.get(a);
            if (info.serverIndex != Integer.MAX_VALUE) {
                this.sortedLanguages.add(info);
            } else {
                this.unofficialLanguages.add(info);
            }
        }
        Collections.sort(this.sortedLanguages, comparator);
        Collections.sort(this.unofficialLanguages, comparator);
    }

    static /* synthetic */ int lambda$fillLanguages$3(LocaleController.LocaleInfo currentLocale, LocaleController.LocaleInfo o, LocaleController.LocaleInfo o2) {
        if (o == currentLocale) {
            return -1;
        }
        if (o2 == currentLocale) {
            return 1;
        }
        if (o.serverIndex == o2.serverIndex) {
            return o.name.compareTo(o2.name);
        }
        if (o.serverIndex > o2.serverIndex) {
            return 1;
        }
        if (o.serverIndex < o2.serverIndex) {
            return -1;
        }
        return 0;
    }

    public void search(final String query) {
        if (query == null) {
            this.searchResult = null;
            return;
        }
        try {
            if (this.searchTimer != null) {
                this.searchTimer.cancel();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        Timer timer = new Timer();
        this.searchTimer = timer;
        timer.schedule(new TimerTask() { // from class: im.uwrkaxlmjj.ui.hui.mine.MryLanguageSelectActivity.3
            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                try {
                    MryLanguageSelectActivity.this.searchTimer.cancel();
                    MryLanguageSelectActivity.this.searchTimer = null;
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                MryLanguageSelectActivity.this.processSearch(query);
            }
        }, 100L, 300L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processSearch(final String query) {
        Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryLanguageSelectActivity$ENl0RNYbM75ct89d2rqLQL25LF0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processSearch$4$MryLanguageSelectActivity(query);
            }
        });
    }

    public /* synthetic */ void lambda$processSearch$4$MryLanguageSelectActivity(String query) {
        String q = query.trim().toLowerCase();
        if (q.length() == 0) {
            updateSearchResults(new ArrayList<>());
            return;
        }
        System.currentTimeMillis();
        ArrayList<LocaleController.LocaleInfo> resultArray = new ArrayList<>();
        int N = this.unofficialLanguages.size();
        for (int a = 0; a < N; a++) {
            LocaleController.LocaleInfo c = this.unofficialLanguages.get(a);
            if (c.name.toLowerCase().contains(query) || c.nameEnglish.toLowerCase().contains(query)) {
                resultArray.add(c);
            }
        }
        int N2 = this.sortedLanguages.size();
        for (int a2 = 0; a2 < N2; a2++) {
            LocaleController.LocaleInfo c2 = this.sortedLanguages.get(a2);
            if ((c2.name.toLowerCase().contains(query) || c2.nameEnglish.toLowerCase().contains(query)) && !resultArray.contains(c2)) {
                resultArray.add(c2);
            }
        }
        updateSearchResults(resultArray);
    }

    private void updateSearchResults(final ArrayList<LocaleController.LocaleInfo> arrCounties) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$MryLanguageSelectActivity$9e73qP78M6vBo4T8MWno3sBqdmM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateSearchResults$5$MryLanguageSelectActivity(arrCounties);
            }
        });
    }

    public /* synthetic */ void lambda$updateSearchResults$5$MryLanguageSelectActivity(ArrayList arrCounties) {
        this.searchResult = arrCounties;
        this.searchListViewAdapter.notifyDataSetChanged();
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private boolean search;

        public ListAdapter(Context context, boolean isSearch) {
            this.mContext = context;
            this.search = isSearch;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (this.search) {
                if (MryLanguageSelectActivity.this.searchResult != null && !MryLanguageSelectActivity.this.searchResult.isEmpty()) {
                    return MryLanguageSelectActivity.this.searchResult.size();
                }
                return 0;
            }
            int count = MryLanguageSelectActivity.this.sortedLanguages.size();
            if (count != 0) {
                count += 2;
            }
            if (!MryLanguageSelectActivity.this.unofficialLanguages.isEmpty()) {
                return count + MryLanguageSelectActivity.this.unofficialLanguages.size() + 1;
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new LanguageCell(this.mContext, false);
                RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, -2);
                layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else {
                view = new View(this.mContext);
                RecyclerView.LayoutParams layoutParams2 = new RecyclerView.LayoutParams(-1, -2);
                layoutParams2.leftMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.rightMargin = AndroidUtilities.dp(10.0f);
                layoutParams2.height = AndroidUtilities.dp(10.0f);
                view.setLayoutParams(layoutParams2);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            LocaleController.LocaleInfo localeInfo;
            boolean last;
            if (holder.getItemViewType() == 0) {
                LanguageCell textSettingsCell = (LanguageCell) holder.itemView;
                if (this.search) {
                    localeInfo = (LocaleController.LocaleInfo) MryLanguageSelectActivity.this.searchResult.get(position);
                    last = position == MryLanguageSelectActivity.this.searchResult.size() - 1;
                } else if (MryLanguageSelectActivity.this.unofficialLanguages.isEmpty() || position < 0 || position >= MryLanguageSelectActivity.this.unofficialLanguages.size()) {
                    if (!MryLanguageSelectActivity.this.unofficialLanguages.isEmpty()) {
                        position -= MryLanguageSelectActivity.this.unofficialLanguages.size() + 1;
                    }
                    localeInfo = (LocaleController.LocaleInfo) MryLanguageSelectActivity.this.sortedLanguages.get(position == 0 ? 0 : position - 1);
                    last = position == MryLanguageSelectActivity.this.sortedLanguages.size();
                } else {
                    localeInfo = (LocaleController.LocaleInfo) MryLanguageSelectActivity.this.unofficialLanguages.get(position);
                    last = position == MryLanguageSelectActivity.this.unofficialLanguages.size() - 1;
                }
                if (localeInfo.isLocal()) {
                    textSettingsCell.setLanguage(localeInfo, String.format("%1$s (%2$s)", localeInfo.name, LocaleController.getString("LanguageCustom", R.string.LanguageCustom)), (last || position == 0) ? false : true);
                } else {
                    textSettingsCell.setLanguage(localeInfo, null, (this.search || position != 0) && !last);
                }
                textSettingsCell.setLanguageSelected(localeInfo == MryLanguageSelectActivity.this.selectedLanguage);
                if ((this.search && getItemCount() == 1) || (!this.search && (localeInfo == LocaleController.getInstance().getCurrentLocaleInfo() || getItemCount() == 3))) {
                    textSettingsCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                if ((this.search && position == 0) || (!this.search && position == 2)) {
                    textSettingsCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                } else if (last) {
                    textSettingsCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (this.search) {
                return 0;
            }
            return ((MryLanguageSelectActivity.this.unofficialLanguages.isEmpty() || !(i == MryLanguageSelectActivity.this.unofficialLanguages.size() || i == (MryLanguageSelectActivity.this.unofficialLanguages.size() + MryLanguageSelectActivity.this.sortedLanguages.size()) + 1)) && !(MryLanguageSelectActivity.this.unofficialLanguages.isEmpty() && (i == 1 || i == MryLanguageSelectActivity.this.sortedLanguages.size() + 1))) ? 0 : 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{LanguageCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{LanguageCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{LanguageCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{LanguageCell.class}, new String[]{"checkImage"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_featuredStickers_addedIcon)};
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onStart(boolean focus) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchExpand() {
        this.searching = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        search(null);
        this.searching = false;
        this.searchWas = false;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            recyclerListView.setAdapter(this.listAdapter);
        }
        EmptyTextProgressView emptyTextProgressView = this.emptyView;
        if (emptyTextProgressView != null) {
            emptyTextProgressView.setVisibility(8);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        search(text);
        if (text.length() != 0) {
            this.searchWas = true;
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                recyclerListView.setAdapter(this.searchListViewAdapter);
                return;
            }
            return;
        }
        onSearchCollapse();
    }
}
