import { render } from 'preact';
import { App } from './app';
import { applyTheme, getTheme } from './state/theme';
import './styles/app.css';

applyTheme(getTheme());
render(<App />, document.getElementById('app')!);
