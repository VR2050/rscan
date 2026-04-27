package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.decoration.StickyDecoration;
import im.uwrkaxlmjj.ui.decoration.listener.GroupListener;
import im.uwrkaxlmjj.ui.hui.CharacterParser;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.sidebar.SideBar;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Pattern;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class CountrySelectActivity extends BaseSearchViewFragment {
    private CountrySelectActivityDelegate delegate;
    private EmptyTextProgressView emptyView;
    private RecyclerListView listView;
    private CountryAdapter listViewAdapter;
    private boolean needChangeChar;
    private boolean needPhoneCode;
    private CountrySearchAdapter searchListViewAdapter;
    private boolean searchWas;
    private boolean searching;
    private SideBar sideBar;

    public static class Country {
        public String code;
        public String name;
        public String phoneFormat;
        public String shortname;
    }

    public interface CountrySelectActivityDelegate {
        void didSelectCountry(Country country);
    }

    public CountrySelectActivity(boolean phoneCode) {
        this.needPhoneCode = phoneCode;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            recyclerListView.setOnScrollListener(null);
        }
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        this.searchView = new MrySearchView(getParentActivity());
        int margin = AndroidUtilities.dp(10.0f);
        ((FrameLayout) this.fragmentView).addView(this.searchView, LayoutHelper.createFrame(-1, 35, margin, margin, margin, margin));
        return this.searchView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        initActionBar();
        super.createView(context);
        initList(frameLayout, context);
        initSideBar(frameLayout, context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("ChooseCountry", R.string.ChooseCountry));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.CountrySelectActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    CountrySelectActivity.this.finishFragment();
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected void initSearchView() {
        super.initSearchView();
        this.searchView.setHintText(LocaleController.getString("Search", R.string.Search));
    }

    private void initList(FrameLayout frameLayout, Context context) {
        CountryAdapter countryAdapter = new CountryAdapter(context);
        this.listViewAdapter = countryAdapter;
        this.searchListViewAdapter = new CountrySearchAdapter(context, countryAdapter.getCountries());
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.showTextView();
        this.emptyView.setShowAtCenter(true);
        this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1, 0, AndroidUtilities.dp(55.0f), 0, 0));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setOverScrollMode(2);
        this.listView.setEmptyView(this.emptyView);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        StickyDecoration.Builder decorationBuilder = StickyDecoration.Builder.init(new GroupListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CountrySelectActivity$NSJWkDIk_GTtf9eZwJBpXXfOtpg
            @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupListener
            public final String getGroupName(int i) {
                return this.f$0.lambda$initList$0$CountrySelectActivity(i);
            }
        }).setGroupBackground(Theme.getColor(Theme.key_windowBackgroundGray)).setGroupTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).setGroupTextTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf")).setGroupHeight(AndroidUtilities.dp(24.0f)).setDivideColor(Color.parseColor("#EE96BC")).setGroupTextSize(AndroidUtilities.dp(14.0f)).setTextSideMargin(AndroidUtilities.dp(15.0f));
        StickyDecoration decoration = decorationBuilder.build();
        this.listView.addItemDecoration(decoration);
        this.listView.addItemDecoration(TopBottomDecoration.getDefaultTopBottomCornerBg(0, 10, 7.5f));
        this.listView.setAdapter(this.listViewAdapter);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(55.0f), AndroidUtilities.dp(10.0f), 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CountrySelectActivity$XxmPujgPylOgxxKmaABd_q8YblU
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$1$CountrySelectActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.CountrySelectActivity.2
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && CountrySelectActivity.this.searching && CountrySelectActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(CountrySelectActivity.this.getParentActivity().getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                LinearLayoutManager layoutManager = (LinearLayoutManager) recyclerView.getLayoutManager();
                int firstPosition = layoutManager.findFirstVisibleItemPosition();
                String s = CountrySelectActivity.this.listViewAdapter.getLetter(firstPosition);
                if (TextUtils.isEmpty(s) && CountrySelectActivity.this.listViewAdapter.getSectionForPosition(firstPosition) == 0) {
                    s = CountrySelectActivity.this.listViewAdapter.getLetter(CountrySelectActivity.this.listViewAdapter.getPositionForSection(1));
                }
                CountrySelectActivity.this.sideBar.setChooseChar(s);
            }
        });
    }

    public /* synthetic */ String lambda$initList$0$CountrySelectActivity(int position) {
        if (this.searchWas) {
            CountrySearchAdapter countrySearchAdapter = this.searchListViewAdapter;
            if (countrySearchAdapter != null && countrySearchAdapter.getItemCount() > 0) {
                String name = this.searchListViewAdapter.getItem(0).name;
                if (!TextUtils.isEmpty(name)) {
                    if (this.needChangeChar) {
                        return CharacterParser.getInstance().getSelling(name).substring(0, 1).toUpperCase();
                    }
                    return name.substring(0, 1).toUpperCase();
                }
                return null;
            }
            return null;
        }
        if (this.listViewAdapter.getItemCount() > position && position > -1) {
            String letter = this.listViewAdapter.getLetter(position);
            return letter;
        }
        return null;
    }

    public /* synthetic */ void lambda$initList$1$CountrySelectActivity(View view, int position) {
        Country country;
        CountrySelectActivityDelegate countrySelectActivityDelegate;
        if (this.searching && this.searchWas) {
            country = this.searchListViewAdapter.getItem(position);
        } else {
            int section = this.listViewAdapter.getSectionForPosition(position);
            int row = this.listViewAdapter.getPositionInSectionForPosition(position);
            if (row < 0 || section < 0) {
                return;
            } else {
                country = this.listViewAdapter.getItem(section, row);
            }
        }
        if (position < 0) {
            return;
        }
        finishFragment();
        if (country != null && (countrySelectActivityDelegate = this.delegate) != null) {
            countrySelectActivityDelegate.didSelectCountry(country);
        }
    }

    private void initSideBar(FrameLayout frameLayout, Context context) {
        TextView textView = new TextView(context);
        textView.setTextSize(50.0f);
        textView.setGravity(17);
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        frameLayout.addView(textView, LayoutHelper.createFrame(100, 100, 17));
        SideBar sideBar = new SideBar(context);
        this.sideBar = sideBar;
        sideBar.setCharsOnly();
        this.sideBar.setTextView(textView);
        frameLayout.addView(this.sideBar, LayoutHelper.createFrame(35.0f, 420.0f, 21, 0.0f, 56.0f, 0.0f, 56.0f));
        this.sideBar.setOnTouchingLetterChangedListener(new SideBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CountrySelectActivity$wWjs0BUK-4wIT9TBRh6_WQiVCZI
            @Override // im.uwrkaxlmjj.ui.hviews.sidebar.SideBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$2$CountrySelectActivity(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$2$CountrySelectActivity(String s) {
        int section = 0;
        if (!"#".equals(s)) {
            section = this.listViewAdapter.getSectionForChar(s.charAt(0));
        }
        int position = this.listViewAdapter.getPositionForSection(section);
        if (position != -1) {
            this.listView.getLayoutManager().scrollToPosition(position);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        CountryAdapter countryAdapter = this.listViewAdapter;
        if (countryAdapter != null) {
            countryAdapter.notifyDataSetChanged();
        }
    }

    public void setCountrySelectActivityDelegate(CountrySelectActivityDelegate delegate) {
        this.delegate = delegate;
    }

    public class CountryAdapter extends RecyclerListView.SectionsAdapter {
        private Context mContext;
        private HashMap<String, ArrayList<Country>> countries = new HashMap<>();
        private ArrayList<String> sortedCountries = new ArrayList<>();

        /* JADX WARN: Removed duplicated region for block: B:14:0x0048  */
        /* JADX WARN: Removed duplicated region for block: B:25:0x0068  */
        /* JADX WARN: Removed duplicated region for block: B:30:0x007b  */
        /* JADX WARN: Removed duplicated region for block: B:56:0x018e A[LOOP:1: B:54:0x0188->B:56:0x018e, LOOP_END] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public CountryAdapter(android.content.Context r20) {
            /*
                Method dump skipped, instruction units count: 411
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.CountrySelectActivity.CountryAdapter.<init>(im.uwrkaxlmjj.ui.CountrySelectActivity, android.content.Context):void");
        }

        public HashMap<String, ArrayList<Country>> getCountries() {
            return this.countries;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Country getItem(int section, int position) {
            if (section < 0 || section >= this.sortedCountries.size()) {
                return null;
            }
            ArrayList<Country> arr = this.countries.get(this.sortedCountries.get(section));
            if (position < 0 || position >= arr.size()) {
                return null;
            }
            return arr.get(position);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            ArrayList<Country> arr = this.countries.get(this.sortedCountries.get(section));
            return row < arr.size();
        }

        public int getSectionForChar(char section) {
            for (int i = 0; i < getSectionCount() - 1; i++) {
                String sortStr = this.sortedCountries.get(i);
                char firstChar = sortStr.toUpperCase().charAt(0);
                if (firstChar == section) {
                    return i;
                }
            }
            return -1;
        }

        public int getPositionForSection(int section) {
            if (section == -1) {
                return -1;
            }
            int positionStart = 0;
            int N = getSectionCount();
            for (int i = 0; i < N; i++) {
                if (i >= section) {
                    return positionStart;
                }
                int count = getCountForSection(i);
                positionStart += count;
            }
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            return this.sortedCountries.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            int count = this.countries.get(this.sortedCountries.get(section)).size();
            if (section != this.sortedCountries.size() - 1) {
                return count + 1;
            }
            return count;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            if (view == null) {
                view = new LetterSectionCell(this.mContext);
                ((LetterSectionCell) view).setCellHeight(AndroidUtilities.dp(48.0f));
            }
            ((LetterSectionCell) view).setLetter(this.sortedCountries.get(section).toUpperCase());
            return view;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new TextSettingsCell(this.mContext);
                view.setPadding(16, 0, 16, 0);
            } else {
                view = new View(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            String str;
            if (holder.getItemViewType() == 0) {
                ArrayList<Country> arr = this.countries.get(this.sortedCountries.get(section));
                Country c = arr.get(position);
                TextSettingsCell textSettingsCell = (TextSettingsCell) holder.itemView;
                String str2 = c.name;
                if (CountrySelectActivity.this.needPhoneCode) {
                    str = Marker.ANY_NON_NULL_MARKER + c.code;
                } else {
                    str = null;
                }
                textSettingsCell.setTextAndValue(str2, str, false);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            ArrayList<Country> arr = this.countries.get(this.sortedCountries.get(section));
            return position < arr.size() ? 0 : 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            int section = getSectionForPosition(position);
            if (section == -1) {
                section = this.sortedCountries.size() - 1;
            }
            return this.sortedCountries.get(section);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return (int) (getItemCount() * progress);
        }
    }

    public class CountrySearchAdapter extends RecyclerListView.SelectionAdapter {
        private HashMap<String, ArrayList<Country>> countries;
        private Context mContext;
        private ArrayList<Country> searchResult;
        private Timer searchTimer;

        public CountrySearchAdapter(Context context, HashMap<String, ArrayList<Country>> countries) {
            this.mContext = context;
            this.countries = countries;
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
            timer.schedule(new TimerTask() { // from class: im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySearchAdapter.1
                @Override // java.util.TimerTask, java.lang.Runnable
                public void run() {
                    try {
                        CountrySearchAdapter.this.searchTimer.cancel();
                        CountrySearchAdapter.this.searchTimer = null;
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                    CountrySearchAdapter.this.processSearch(query.toLowerCase());
                }
            }, 100L, 300L);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void processSearch(final String query) {
            Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CountrySelectActivity$CountrySearchAdapter$_khUZ1-H9UGYKi2LQbAr0ISrC1o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processSearch$0$CountrySelectActivity$CountrySearchAdapter(query);
                }
            });
        }

        public /* synthetic */ void lambda$processSearch$0$CountrySelectActivity$CountrySearchAdapter(String query) {
            String q = query.trim().toLowerCase();
            if (q.length() == 0) {
                updateSearchResults(new ArrayList<>());
                return;
            }
            ArrayList<Country> resultArray = new ArrayList<>();
            boolean isInputEn = Pattern.compile("([a-zA-Z])").matcher(query).matches();
            String n = query.substring(0, 1).toUpperCase();
            if (!isInputEn) {
                n = CharacterParser.getInstance().getSelling(n).toUpperCase();
                if (n.length() > 1) {
                    n = n.substring(0, 1);
                }
            }
            ArrayList<Country> arr = this.countries.get(n);
            if (arr != null) {
                for (Country c : arr) {
                    if (CountrySelectActivity.this.needChangeChar) {
                        if (!isInputEn) {
                            if (c.name.toLowerCase().startsWith(query)) {
                                resultArray.add(c);
                            }
                        } else if (CharacterParser.getInstance().getSelling(c.name).toLowerCase().startsWith(query)) {
                            resultArray.add(c);
                        }
                    } else if (c.name.toLowerCase().startsWith(query)) {
                        resultArray.add(c);
                    }
                }
            }
            updateSearchResults(resultArray);
        }

        private void updateSearchResults(final ArrayList<Country> arrCounties) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CountrySelectActivity$CountrySearchAdapter$NpNsmMFXBNhiXeO1UWUhveC3nJo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$1$CountrySelectActivity$CountrySearchAdapter(arrCounties);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$1$CountrySelectActivity$CountrySearchAdapter(ArrayList arrCounties) {
            this.searchResult = arrCounties;
            notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            ArrayList<Country> arrayList = this.searchResult;
            if (arrayList == null) {
                return 0;
            }
            return arrayList.size();
        }

        public Country getItem(int i) {
            if (i < 0 || i >= this.searchResult.size()) {
                return null;
            }
            return this.searchResult.get(i);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            return new RecyclerListView.Holder(new TextSettingsCell(this.mContext));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String str;
            Country c = this.searchResult.get(position);
            TextSettingsCell textSettingsCell = (TextSettingsCell) holder.itemView;
            String str2 = c.name;
            if (CountrySelectActivity.this.needPhoneCode) {
                str = Marker.ANY_NON_NULL_MARKER + c.code;
            } else {
                str = null;
            }
            textSettingsCell.setTextAndValue(str2, str, position != this.searchResult.size() - 1);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollActive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollInactive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollText), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_SECTIONS, new Class[]{LetterSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4)};
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
        CountrySearchAdapter countrySearchAdapter = this.searchListViewAdapter;
        if (countrySearchAdapter != null) {
            countrySearchAdapter.search(null);
        }
        this.searching = false;
        this.searchWas = false;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            recyclerListView.setAdapter(this.listViewAdapter);
            this.listView.setFastScrollVisible(false);
        }
        EmptyTextProgressView emptyTextProgressView = this.emptyView;
        if (emptyTextProgressView != null) {
            emptyTextProgressView.setText(LocaleController.getString("ChooseCountry", R.string.ChooseCountry));
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        this.searchListViewAdapter.search(text);
        if (text.length() != 0) {
            this.searchWas = true;
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                recyclerListView.setAdapter(this.searchListViewAdapter);
                this.listView.setFastScrollVisible(false);
            }
            EmptyTextProgressView emptyTextProgressView = this.emptyView;
            return;
        }
        onSearchCollapse();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onActionSearch(String trim) {
    }
}
