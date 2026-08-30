import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ConfigProvider, Layout } from 'antd';

import { useTheme } from '@/hooks/useTheme';
import AppSidebar from '@/layouts/AppSidebar';
import './TunnelPage.css';

const basePath = window.X_UI_BASE_PATH || '';
// The tunnel panel is reached through Ex-ui's own reverse proxy, so it rides the
// panel's port and session instead of exposing one of its own.
const tunnelSrc = `${basePath}panel/packet/`;

export default function TunnelPage() {
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { t } = useTranslation();

  const pageClass = useMemo(() => {
    const classes = ['tunnel-page'];
    if (isDark) classes.push('is-dark');
    if (isUltra) classes.push('is-ultra');
    return classes.join(' ');
  }, [isDark, isUltra]);

  return (
    <ConfigProvider theme={antdThemeConfig}>
      <Layout className={pageClass}>
        <AppSidebar />

        <Layout className="content-shell">
          <Layout.Content className="content-area">
            <div className="tunnel-wrapper" role="region" aria-label={t('menu.tunnel')}>
              <iframe src={tunnelSrc} className="tunnel-frame" title={t('menu.tunnel')} />
            </div>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
