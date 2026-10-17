package com.glass.protector.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.glass.protector.R;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

public class HomeFragment extends Fragment {

    private ViewPager2 viewPager;
    private TabLayout tabLayout;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_home, container, false);
        viewPager = view.findViewById(R.id.homeViewPager);
        tabLayout = view.findViewById(R.id.homeTabLayout);
        setupViewPager();
        return view;
    }

    private void setupViewPager() {
        FragmentActivity activity = requireActivity();
        FragmentStateAdapter adapter = new FragmentStateAdapter(activity) {
            @NonNull
            @Override
            public Fragment createFragment(int position) {
                if (position == 0) return new DptProtectFragment();
                return new GlassProtectFragment();
            }

            @Override
            public int getItemCount() { return 2; }
        };
        viewPager.setAdapter(adapter);
        viewPager.setOffscreenPageLimit(2);

        final String[] titles = {getString(R.string.tab_dpt), getString(R.string.tab_glass)};
        new TabLayoutMediator(tabLayout, viewPager,
                (tab, position) -> tab.setText(titles[position])
        ).attach();
    }
}
