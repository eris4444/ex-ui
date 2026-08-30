import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { ConfigProvider, Layout } from 'antd';

import { useTheme } from '@/hooks/useTheme';
import AppSidebar from '@/layouts/AppSidebar';
import './PacketPage.css';

const basePath = window.X_UI_BASE_PATH || '';
const packetSrc = `${basePath}panel/packet/`;

export default function PacketPage() {
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const { t } = useTranslation();

  const pageClass = useMemo(() => {
    const classes = ['packet-page'];
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
            <div className="packet-wrapper" role="region" aria-label={t('menu.packet')}>
              <iframe src={packetSrc} className="packet-frame" title={t('menu.packet')} />
            </div>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
