%===============================================================================
%     File: char_test.m
%  Created: 07/06/2017, 16:51
%   Author: Bernie Roesler
%
%  Description: 
%
%===============================================================================
clear; close all;

str = { upper('Anything less than the best is a felony.');
        upper('Now that the party is jumping ');
        upper('nOWTHATTHEPARTYISJUMPING*');
        upper('Cooking MC''s like a pound of bacon');
        upper('Hs>u1Y/orf:AP|m@?v:9') };

alph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

Na = length(alph);
Ns = numel(str);
cnt   = zeros(Na,Ns);
chi_sq = zeros(Na,Ns);
Chi_sq = zeros(1,Ns);
score = zeros(1,Ns);

english_freq = [ 0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, ...
          0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, ...
          0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, ...
          0.00978, 0.02360, 0.00150, 0.01974, 0.00074 ]';

for j = 1:Ns
    s = str{j};

    for i = 1:Na
        N = length(s);
        % Nl = sum(isletter(s)); % count just letters
        Nl = sum(isspace(s) | isletter(s)); % count letters + spaces
        
        cnt(i,j) = count(s, alph(i));

        % Use frequencies
        chi_sq(i,j) = (cnt(i,j) - english_freq(i)*N)^2 / (english_freq(i)*N);
    end

    % multiply by N for standard definition ("counts" not "freqs")
    Chi_sq(j) = sum(chi_sq(:,j));
    letter_frac = Nl/N;
    score(j) = Chi_sq(j) / letter_frac^2;
end

fprintf('%20.16f\n', score(:));
%===============================================================================
%===============================================================================
