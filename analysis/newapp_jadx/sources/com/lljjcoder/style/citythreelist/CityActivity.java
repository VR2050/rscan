package com.lljjcoder.style.citythreelist;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.lljjcoder.style.citylist.bean.CityInfoBean;
import com.lljjcoder.style.citylist.utils.CityListLoader;
import com.lljjcoder.style.citypickerview.C3949R;
import com.lljjcoder.style.citythreelist.CityAdapter;
import com.lljjcoder.widget.RecycleViewDividerForList;
import java.util.ArrayList;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class CityActivity extends Activity {
    private TextView mCityNameTv;
    private RecyclerView mCityRecyclerView;
    private ImageView mImgBack;
    private CityInfoBean mProInfo = null;
    private String cityName = "";
    private CityBean cityBean = new CityBean();
    private CityBean area = new CityBean();

    private void initView() {
        this.mImgBack = (ImageView) findViewById(C3949R.id.img_left);
        int i2 = C3949R.id.cityname_tv;
        this.mCityNameTv = (TextView) findViewById(i2);
        this.mImgBack.setVisibility(0);
        this.mImgBack.setOnClickListener(new View.OnClickListener() { // from class: com.lljjcoder.style.citythreelist.CityActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                CityActivity.this.finish();
            }
        });
        this.mCityNameTv = (TextView) findViewById(i2);
        RecyclerView recyclerView = (RecyclerView) findViewById(C3949R.id.city_recyclerview);
        this.mCityRecyclerView = recyclerView;
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        this.mCityRecyclerView.addItemDecoration(new RecycleViewDividerForList((Context) this, 0, true));
    }

    private void setData(CityInfoBean cityInfoBean) {
        if (cityInfoBean == null || cityInfoBean.getCityList().size() <= 0) {
            return;
        }
        TextView textView = this.mCityNameTv;
        StringBuilder m586H = C1499a.m586H("");
        m586H.append(cityInfoBean.getName());
        textView.setText(m586H.toString());
        final ArrayList<CityInfoBean> cityList = cityInfoBean.getCityList();
        if (cityList == null) {
            return;
        }
        CityAdapter cityAdapter = new CityAdapter(this, cityList);
        this.mCityRecyclerView.setAdapter(cityAdapter);
        cityAdapter.setOnItemClickListener(new CityAdapter.OnItemSelectedListener() { // from class: com.lljjcoder.style.citythreelist.CityActivity.1
            @Override // com.lljjcoder.style.citythreelist.CityAdapter.OnItemSelectedListener
            public void onItemSelected(View view, int i2) {
                CityActivity.this.cityBean.setId(((CityInfoBean) cityList.get(i2)).getId());
                CityActivity.this.cityBean.setName(((CityInfoBean) cityList.get(i2)).getName());
                Intent intent = new Intent(CityActivity.this, (Class<?>) AreaActivity.class);
                intent.putExtra(CityListLoader.BUNDATA, (Parcelable) cityList.get(i2));
                CityActivity.this.startActivityForResult(intent, 1001);
            }
        });
    }

    @Override // android.app.Activity
    public void onActivityResult(int i2, int i3, Intent intent) {
        super.onActivityResult(i2, i3, intent);
        if (i3 != 1001 || intent == null) {
            return;
        }
        this.area = (CityBean) intent.getParcelableExtra("area");
        Intent intent2 = new Intent();
        intent2.putExtra("city", this.cityBean);
        intent2.putExtra("area", this.area);
        setResult(-1, intent2);
        finish();
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C3949R.layout.activity_citylist);
        this.mProInfo = (CityInfoBean) getIntent().getParcelableExtra(CityListLoader.BUNDATA);
        initView();
        setData(this.mProInfo);
    }

    @Override // android.app.Activity
    public void onDestroy() {
        super.onDestroy();
    }
}
